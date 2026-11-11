// Package wal provides a crash-safe, size-bounded write-ahead log for metrics
// batches. Records are length-and-checksum framed so a torn write is detected
// and truncated instead of corrupting later reads.
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	// ErrCorrupt marks a record whose checksum or framing is invalid.
	ErrCorrupt = errors.New("wal: corrupt record")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("wal: closed")
)

const (
	headerSize = 8
	segSuffix  = ".seg"
)

// Position points at the start of a record.
type Position struct {
	Seg uint64 `json:"seg"`
	Off int64  `json:"off"`
}

func (p Position) String() string { return fmt.Sprintf("%010d@%d", p.Seg, p.Off) }

// Before reports whether p is strictly older than q.
func (p Position) Before(q Position) bool {
	if p.Seg != q.Seg {
		return p.Seg < q.Seg
	}
	return p.Off < q.Off
}

type WAL struct {
	dir      string
	maxBytes int64
	segSize  int64

	mu      sync.Mutex
	segs    map[uint64]int64 // segment id -> size
	cur     uint64
	curFile *os.File
	curSize int64
	ack     Position
	total   int64
	closed  bool
}

// Open scans dir and prepares the newest segment for appending. Incomplete
// trailing records from a crash are truncated.
func Open(dir string, maxBytes, segSize int64) (*WAL, error) {
	if segSize <= 0 {
		segSize = 1 << 20
	}
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	if maxBytes < segSize {
		maxBytes = segSize
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &WAL{dir: dir, maxBytes: maxBytes, segSize: segSize, segs: map[uint64]int64{}}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	for _, e := range entries {
		id, ok := parseSegName(e.Name())
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		w.segs[id] = info.Size()
		w.total += info.Size()
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		w.cur = 1
		f, err := os.OpenFile(w.segPath(w.cur), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		f.Close()
		w.segs[w.cur] = 0
	} else {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		w.cur = ids[len(ids)-1]
	}

	if err := w.repair(w.cur); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(w.segPath(w.cur), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	w.curFile = f
	w.curSize = w.segs[w.cur]
	return w, nil
}

func (w *WAL) segPath(id uint64) string {
	return filepath.Join(w.dir, fmt.Sprintf("%010d%s", id, segSuffix))
}

func parseSegName(name string) (uint64, bool) {
	if !strings.HasSuffix(name, segSuffix) {
		return 0, false
	}
	id, err := strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// repair truncates the segment at the first invalid record so appends never
// follow garbage.
func (w *WAL) repair(id uint64) error {
	path := w.segPath(id)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	var off int64
	for off+headerSize <= size {
		var hdr [headerSize]byte
		if _, err := f.ReadAt(hdr[:], off); err != nil {
			break
		}
		n := int64(binary.LittleEndian.Uint32(hdr[0:4]))
		if n <= 0 || off+headerSize+n > size {
			break
		}
		payload := make([]byte, n)
		if _, err := f.ReadAt(payload, off+headerSize); err != nil {
			break
		}
		if crc32.ChecksumIEEE(payload) != binary.LittleEndian.Uint32(hdr[4:8]) {
			break
		}
		off += headerSize + n
	}
	if off != size {
		if err := f.Truncate(off); err != nil {
			return err
		}
		w.total -= size - off
		w.segs[id] = off
	}
	return nil
}

// Append writes one record and syncs it. Callers batch samples upstream, so a
// sync per record is acceptable at a 5s cadence.
func (w *WAL) Append(payload []byte) (Position, error) {
	if len(payload) == 0 {
		return Position{}, fmt.Errorf("wal: empty record")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Position{}, ErrClosed
	}
	need := int64(headerSize + len(payload))
	if w.curSize > 0 && w.curSize+need > w.segSize {
		if err := w.rotateLocked(); err != nil {
			return Position{}, err
		}
	}

	pos := Position{Seg: w.cur, Off: w.curSize}
	buf := make([]byte, headerSize+len(payload))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(buf[4:8], crc32.ChecksumIEEE(payload))
	copy(buf[headerSize:], payload)
	if _, err := w.curFile.Write(buf); err != nil {
		return Position{}, err
	}
	if err := w.curFile.Sync(); err != nil {
		return Position{}, err
	}
	w.curSize += need
	w.segs[w.cur] = w.curSize
	w.total += need
	w.enforceLocked()
	return pos, nil
}

func (w *WAL) rotateLocked() error {
	if err := w.curFile.Close(); err != nil {
		return err
	}
	w.cur++
	w.curSize = 0
	w.segs[w.cur] = 0
	f, err := os.OpenFile(w.segPath(w.cur), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.curFile = f
	return nil
}

// SetAck marks everything before pos as delivered. Fully acked segments are
// deleted; when the current segment is fully acked it is rotated first so
// reader positions stay monotonic.
func (w *WAL) SetAck(pos Position) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.ack.Before(pos) {
		return
	}
	w.ack = pos
	if w.ack.Seg == w.cur && w.ack.Off >= w.curSize && w.curSize > 0 {
		if err := w.rotateLocked(); err != nil {
			return
		}
	}
	w.enforceLocked()
}

// enforceLocked deletes fully acked segments, then trims the oldest unacked
// segments if the size budget is exceeded. The active segment is never removed.
func (w *WAL) enforceLocked() {
	ids := make([]uint64, 0, len(w.segs))
	for id := range w.segs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		if id == w.cur {
			continue
		}
		size := w.segs[id]
		if id < w.ack.Seg || (id == w.ack.Seg && w.ack.Off >= size) {
			if err := os.Remove(w.segPath(id)); err == nil {
				w.total -= size
				delete(w.segs, id)
			}
		}
	}

	if w.total <= w.maxBytes {
		return
	}
	for _, id := range ids {
		if w.total <= w.maxBytes {
			return
		}
		if id >= w.ack.Seg || id == w.cur {
			return
		}
		if err := os.Remove(w.segPath(id)); err == nil {
			w.total -= w.segs[id]
			delete(w.segs, id)
		}
	}
}

// Iterator walks records starting at pos. It never blocks on future writes:
// reaching the end of the newest segment yields io.EOF.
type Iterator struct {
	w   *WAL
	pos Position
}

func (w *WAL) Iterator(pos Position) *Iterator { return &Iterator{w: w, pos: pos} }

// SkipSegment abandons the current segment and returns the next position.
func (it *Iterator) SkipSegment() Position {
	it.pos = Position{Seg: it.pos.Seg + 1, Off: 0}
	return it.pos
}

// Next returns the next record and the position immediately after it.
func (it *Iterator) Next() ([]byte, Position, error) {
	it.w.mu.Lock()
	defer it.w.mu.Unlock()
	if it.w.closed {
		return nil, Position{}, ErrClosed
	}
	for {
		seg := it.pos.Seg
		off := it.pos.Off

		if _, ok := it.w.segs[seg]; !ok {
			next, ok := it.w.firstSegAtLeast(seg)
			if !ok {
				return nil, Position{}, io.EOF
			}
			it.pos = Position{Seg: next, Off: 0}
			continue
		}

		size := it.w.segs[seg]
		if off >= size {
			next, ok := it.w.nextSeg(seg)
			if !ok {
				return nil, Position{}, io.EOF
			}
			it.pos = Position{Seg: next, Off: 0}
			continue
		}
		if off+headerSize > size {
			return nil, Position{}, ErrCorrupt
		}

		f, err := os.Open(it.w.segPath(seg))
		if err != nil {
			// Segment vanished between checks (rotation race): retry.
			if os.IsNotExist(err) {
				continue
			}
			return nil, Position{}, err
		}
		var hdr [headerSize]byte
		_, err = f.ReadAt(hdr[:], off)
		if err != nil {
			f.Close()
			return nil, Position{}, err
		}
		n := int64(binary.LittleEndian.Uint32(hdr[0:4]))
		if n <= 0 || off+headerSize+n > size {
			f.Close()
			return nil, Position{}, ErrCorrupt
		}
		payload := make([]byte, n)
		if _, err := f.ReadAt(payload, off+headerSize); err != nil {
			f.Close()
			return nil, Position{}, err
		}
		f.Close()
		if crc32.ChecksumIEEE(payload) != binary.LittleEndian.Uint32(hdr[4:8]) {
			return nil, Position{}, ErrCorrupt
		}
		next := Position{Seg: seg, Off: off + headerSize + n}
		it.pos = next
		return payload, next, nil
	}
}

func (w *WAL) firstSegAtLeast(id uint64) (uint64, bool) {
	best := uint64(0)
	found := false
	for seg := range w.segs {
		if seg >= id && (!found || seg < best) {
			best, found = seg, true
		}
	}
	return best, found
}

func (w *WAL) nextSeg(id uint64) (uint64, bool) {
	best := uint64(0)
	found := false
	for seg := range w.segs {
		if seg > id && (!found || seg < best) {
			best, found = seg, true
		}
	}
	return best, found
}

// Bytes returns the on-disk size of all segments.
func (w *WAL) Bytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total
}

// PendingBytes returns the unacknowledged payload size, which is what actually
// needs to reach the center.
func (w *WAL) PendingBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var n int64
	for id, size := range w.segs {
		switch {
		case id < w.ack.Seg:
			continue
		case id == w.ack.Seg:
			if w.ack.Off < size {
				n += size - w.ack.Off
			}
		default:
			n += size
		}
	}
	return n
}

// Segments returns the segment ids, oldest first. Used by tests.
func (w *WAL) Segments() []uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids := make([]uint64, 0, len(w.segs))
	for id := range w.segs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.curFile.Close()
}
