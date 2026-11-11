package collector

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/yqjwxz/beacon/internal/procfs"
)

// pseudoFS lists filesystems that do not represent real storage and would only
// add noise. overlay and tmpfs are kept: they commonly are the root filesystem
// inside containers and are worth watching.
var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"cgroup": true, "cgroup2": true, "securityfs": true, "debugfs": true,
	"tracefs": true, "configfs": true, "fusectl": true, "bpf": true,
	"pstore": true, "autofs": true, "mqueue": true, "hugetlbfs": true,
	"binfmt_misc": true, "nsfs": true, "rpc_pipefs": true, "selinuxfs": true,
	"efivarfs": true, "fuse.gvfsd-fuse": true, "fuse.portal": true,
}

type mount struct {
	Device     string
	Mountpoint string
	FSType     string
	ReadOnly   bool
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(
		`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`,
	)
	return r.Replace(s)
}

func parseMounts(b []byte) []mount {
	var out []mount
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mp := unescapeMount(fields[1])
		fstype := fields[2]
		if pseudoFS[fstype] || seen[mp] {
			continue
		}
		seen[mp] = true
		out = append(out, mount{
			Device:     unescapeMount(fields[0]),
			Mountpoint: mp,
			FSType:     fstype,
			ReadOnly:   hasOpt(fields[3], "ro"),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mountpoint < out[j].Mountpoint })
	return out
}

func hasOpt(opts, want string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == want {
			return true
		}
	}
	return false
}

type ioStats struct {
	Reads, Writes               uint64
	SectorsRead, SectorsWritten uint64
	IOMs, WeightedIOMs          uint64
	InFlight                    uint64
}

func parseDiskstats(b []byte) map[string]ioStats {
	out := map[string]ioStats{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		u := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		out[f[2]] = ioStats{
			Reads: u(3), SectorsRead: u(5),
			Writes: u(7), SectorsWritten: u(9),
			InFlight: u(11), IOMs: u(12), WeightedIOMs: u(13),
		}
	}
	return out
}

// isWholeDevice filters out loop devices, partitions and virtual block devices.
// When sysfs is available it is authoritative; the name pattern is a fallback.
func isWholeDevice(src *procfs.Source, name string) bool {
	if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
		strings.HasPrefix(name, "zram") || strings.HasPrefix(name, "sr") {
		return false
	}
	if src.ExistsSys("block", name) {
		return true
	}
	// No sysfs entry: accept only names that look like whole devices.
	if strings.HasPrefix(name, "nvme") {
		return !strings.Contains(name, "p")
	}
	for _, p := range []string{"sd", "vd", "xvd", "hd", "mmcblk"} {
		if strings.HasPrefix(name, p) {
			rest := strings.TrimPrefix(name, p)
			for _, r := range rest {
				if r < 'a' || r > 'z' {
					return false // sda1 / mmcblk0p1
				}
			}
			return rest != ""
		}
	}
	return strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "md")
}

type fsSnapshot struct {
	mount      mount
	size       float64
	avail      float64
	usedRatio  float64
	inodeRatio float64
	readOnly   bool
	present    bool
}

type ioSnapshot struct {
	device  string
	stats   ioStats
	await   float64
	util    float64
	iopsR   float64
	iopsW   float64
	hasRate bool
}

type Disk struct {
	base
	src      *procfs.Source
	interval time.Duration
	exclude  *regexp.Regexp

	mu     sync.RWMutex
	fs     []fsSnapshot
	io     []ioSnapshot
	prevIO map[string]ioStats
	prevAt time.Time

	dSize, dAvail, dUsed, dInode, dRO, dPresent *prometheus.Desc
	dRead, dWrite, dIops, dAwait, dUtil         *prometheus.Desc
}

func NewDisk(src *procfs.Source, host string, interval time.Duration, exclude *regexp.Regexp) *Disk {
	b := base{host: host}
	return &Disk{
		base: b, src: src, interval: interval, exclude: exclude,
		dSize:    b.desc("beacon_disk_size_bytes", "Filesystem size.", "mount", "device", "fstype"),
		dAvail:   b.desc("beacon_disk_avail_bytes", "Filesystem bytes available to unprivileged users.", "mount", "device", "fstype"),
		dUsed:    b.desc("beacon_disk_used_ratio", "Filesystem space used as a fraction of total.", "mount", "device"),
		dInode:   b.desc("beacon_disk_inode_used_ratio", "Inodes used as a fraction of total.", "mount", "device"),
		dRO:      b.desc("beacon_disk_readonly", "Filesystem is mounted read-only.", "mount", "device"),
		dPresent: b.desc("beacon_disk_mount_present", "Mountpoint is currently present.", "mount", "device"),
		dRead:    b.desc("beacon_disk_read_bytes_total", "Bytes read from the device.", "device"),
		dWrite:   b.desc("beacon_disk_write_bytes_total", "Bytes written to the device.", "device"),
		dIops:    b.desc("beacon_disk_iops", "I/O operations per second over the last interval.", "device", "op"),
		dAwait:   b.desc("beacon_disk_await_seconds", "Average time per I/O operation over the last interval.", "device"),
		dUtil:    b.desc("beacon_disk_util_ratio", "Fraction of wall time the device had I/O in flight.", "device"),
	}
}

func (d *Disk) Name() string            { return "disk" }
func (d *Disk) Interval() time.Duration { return d.interval }

func (d *Disk) Refresh(ctx context.Context) error {
	var fs []fsSnapshot
	if raw, err := d.src.ReadProc("mounts"); err == nil {
		for _, m := range parseMounts(raw) {
			if d.exclude != nil && d.exclude.MatchString(m.Mountpoint) {
				continue
			}
			s := fsSnapshot{mount: m}
			var st unix.Statfs_t
			if err := unix.Statfs(m.Mountpoint, &st); err != nil {
				s.present = false
				fs = append(fs, s)
				continue
			}
			bsize := float64(st.Bsize)
			s.present = true
			s.size = float64(st.Blocks) * bsize
			s.avail = float64(st.Bavail) * bsize
			if st.Blocks > 0 {
				s.usedRatio = float64(st.Blocks-st.Bfree) / float64(st.Blocks)
			}
			if st.Files > 0 {
				s.inodeRatio = float64(st.Files-st.Ffree) / float64(st.Files)
			}
			s.readOnly = m.ReadOnly || st.Flags&unix.ST_RDONLY != 0
			fs = append(fs, s)
		}
	} else {
		return err
	}

	rawIO, err := d.src.ReadProc("diskstats")
	if err != nil {
		return err
	}
	cur := parseDiskstats(rawIO)
	now := time.Now()

	var ioS []ioSnapshot
	dt := now.Sub(d.prevAt).Seconds()
	for name, st := range cur {
		if !isWholeDevice(d.src, name) {
			continue
		}
		s := ioSnapshot{device: name, stats: st}
		if prev, ok := d.prevIO[name]; ok && dt > 0 {
			dOps := float64(delta(st.Reads, prev.Reads) + delta(st.Writes, prev.Writes))
			dWIO := float64(delta(st.WeightedIOMs, prev.WeightedIOMs))
			dIO := float64(delta(st.IOMs, prev.IOMs))
			s.iopsR = float64(delta(st.Reads, prev.Reads)) / dt
			s.iopsW = float64(delta(st.Writes, prev.Writes)) / dt
			if dOps > 0 {
				s.await = dWIO / 1000 / dOps
			}
			s.util = dIO / 1000 / dt
			if s.util > 1 {
				s.util = 1
			}
			s.hasRate = true
		}
		ioS = append(ioS, s)
	}

	d.mu.Lock()
	d.fs = fs
	d.io = ioS
	d.prevIO = cur
	d.prevAt = now
	d.mu.Unlock()
	return nil
}

func (d *Disk) Describe(ch chan<- *prometheus.Desc) {
	for _, x := range []*prometheus.Desc{
		d.dSize, d.dAvail, d.dUsed, d.dInode, d.dRO, d.dPresent,
		d.dRead, d.dWrite, d.dIops, d.dAwait, d.dUtil,
	} {
		ch <- x
	}
}

func (d *Disk) Collect(ch chan<- prometheus.Metric) {
	d.mu.RLock()
	fs, io := d.fs, d.io
	d.mu.RUnlock()

	for _, s := range fs {
		l := []string{s.mount.Mountpoint, s.mount.Device, s.mount.FSType}
		present := 0.0
		if s.present {
			present = 1
		}
		ch <- prometheus.MustNewConstMetric(d.dSize, prometheus.GaugeValue, s.size, l...)
		ch <- prometheus.MustNewConstMetric(d.dAvail, prometheus.GaugeValue, s.avail, l...)
		ch <- prometheus.MustNewConstMetric(d.dUsed, prometheus.GaugeValue, s.usedRatio, l[0], l[1])
		ch <- prometheus.MustNewConstMetric(d.dInode, prometheus.GaugeValue, s.inodeRatio, l[0], l[1])
		ro := 0.0
		if s.readOnly {
			ro = 1
		}
		ch <- prometheus.MustNewConstMetric(d.dRO, prometheus.GaugeValue, ro, l[0], l[1])
		ch <- prometheus.MustNewConstMetric(d.dPresent, prometheus.GaugeValue, present, l[0], l[1])
	}

	for _, s := range io {
		ch <- prometheus.MustNewConstMetric(d.dRead, prometheus.CounterValue, float64(s.stats.SectorsRead)*512, s.device)
		ch <- prometheus.MustNewConstMetric(d.dWrite, prometheus.CounterValue, float64(s.stats.SectorsWritten)*512, s.device)
		if s.hasRate {
			ch <- prometheus.MustNewConstMetric(d.dIops, prometheus.GaugeValue, s.iopsR, s.device, "read")
			ch <- prometheus.MustNewConstMetric(d.dIops, prometheus.GaugeValue, s.iopsW, s.device, "write")
			ch <- prometheus.MustNewConstMetric(d.dAwait, prometheus.GaugeValue, s.await, s.device)
			ch <- prometheus.MustNewConstMetric(d.dUtil, prometheus.GaugeValue, s.util, s.device)
		}
	}
}
