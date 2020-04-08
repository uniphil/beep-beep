package traffic_data

import (
	"fmt"
	"github.com/go-redis/redis"
	"math"
	"time"
	"sort"
	"strconv"
	"strings"
)

var DATE_FORMAT = "20060102"
var rdb      *redis.Client

type Pulse []struct {
	T time.Time
	Count int64
}

func (pulse Pulse) Points(w, h int64) []PulsePoint {
	PADDING := int64(2)
	tmin := time.Now()
	tmax := time.Unix(0, 0)
	cmin := int64(0)
	cmax := int64(1)
	for _, p := range pulse {
		if p.T.Before(tmin) {
			tmin = p.T
		}
		if p.T.After(tmax) {
			tmax = p.T
		}
		if p.Count < cmin {
			cmin = p.Count
		}
		if p.Count > cmax {
			cmax = p.Count
		}
	}
	tfmin := tmin.Unix()
	tfmax := tmax.Unix()
	xscale := float64(w-PADDING*2)/float64(tfmax-tfmin)
	var out []PulsePoint
	for _, p := range pulse {
		out = append(out, PulsePoint{
			X: float64(p.T.Unix()-tfmin)*xscale + float64(PADDING),
			Y: float64(p.Count * (h-PADDING*2)) / float64(cmax) + float64(PADDING),
			T: p.T,
			Count: p.Count,
		})
	}
	return out
}

type PulsePoint struct {
	X, Y float64
	T time.Time
	Count int64
}

type Data []struct {
	X time.Time
	Y int64
}

func (data *Data) ToPulse() Pulse {
	var out Pulse
	for _, d := range *data {
		out = append(out, struct{ T time.Time; Count int64 }{
			T: d.X,
			Count: d.Y,
		})
	}
	return out
}

type GraphData struct {
	H, W int64
	Data Data
	Name string
}

type PathTraffic struct {
	Path    string
	Traffic Traffic
}

type Traffic struct {
	Visitors  int64
	T 			time.Time
	Pageviews int64
}


func Estimate_visitors(pageviews int64, dnt_pageviews int64, visitors int64) int64 {
	var dnt_visitors int64
	if dnt_pageviews > 0 {
		if pageviews > 0 {
			dnt_rate := float64(dnt_pageviews) / float64(dnt_pageviews+pageviews)
			dnt_visitors = int64(math.Round(float64(visitors) * dnt_rate))
		} else {
			dnt_visitors = 1
		}
	}
	return visitors + dnt_visitors
}

func PathsSummary(host string, host_key string, start time.Time, end time.Time) ([]PathTraffic, error) {
	start = start.AddDate(0, 0, 1)
	end = end.AddDate(0, 0, 1)
	summary := make(map[string]Traffic)
	path_hll_keys := make(map[string][]string)
	path_abs_keys := make(map[string][]string)
	for t := start; t.Before(end); t = t.AddDate(0, 0, 1) {
		date_key := t.Format(DATE_FORMAT)

		hll_keys, _ := rdb.Keys(fmt.Sprintf("counts:hll:%s:%s:%s:*", host, host_key, date_key)).Result()
		for _, key := range hll_keys {
			path := strings.SplitN(key, ":", 5)[4]
			path_hll_keys[path] = append(path_hll_keys[path], key)
		}

		abs_keys, _ := rdb.Keys(fmt.Sprintf("counts:abs:%s:%s:%s:*", host, host_key, date_key)).Result()
		for _, key := range abs_keys {
			path := strings.SplitN(key, ":", 5)[4]
			path_abs_keys[path] = append(path_abs_keys[path], key)
		}
	}

	for path, keys := range path_hll_keys {
		count, _ := rdb.PFCount(keys...).Result()
		summary[path] = Traffic{
			Visitors: count,
		}
	}

	for path, keys := range path_abs_keys {
		counts, _ := rdb.MGet(keys...).Result()
		var pageviews int64
		for _, count := range counts {
			n, _ := strconv.ParseInt(count.(string), 10, 64)
			pageviews += n
		}
		summary[path] = Traffic{
			Visitors:  summary[path].Visitors,
			Pageviews: pageviews,
		}
	}

	var sorted []PathTraffic
	for k, v := range summary {
		sorted = append(sorted, PathTraffic{Path: k, Traffic: v})
	}
	sort.Slice(sorted, func(a, b int) bool {
		at, bt := sorted[a].Traffic, sorted[b].Traffic
		if at.Visitors == bt.Visitors {
			return bt.Pageviews < at.Pageviews
		}
		return bt.Visitors < at.Visitors
	})

	return sorted, nil
}

func HostSummary(host string, host_key string, start time.Time, end time.Time) (Traffic, []Traffic, error) {
	start = start.AddDate(0, 0, 1)
	end = end.AddDate(0, 0, 1)
	var (
		daily_traffic         []Traffic
		monthly_pageviews     int64
		monthly_dnt_pageviews int64
		monthly_hll_keys      []string
	)
	for t := start; t.Before(end); t = t.AddDate(0, 0, 1) {
		date_key := t.Format(DATE_FORMAT)

		var visitors int64
		hll_keys, err := rdb.Keys(fmt.Sprintf("counts:hll:%s:%s:%s:*", host, host_key, date_key)).Result()
		if err == nil && len(hll_keys) > 0 {
			visitors += rdb.PFCount(hll_keys...).Val()
		}

		var pageviews int64
		abs_keys, err := rdb.Keys(fmt.Sprintf("counts:abs:%s:%s:%s:*", host, host_key, date_key)).Result()
		if err == nil && len(abs_keys) > 0 {
			counters := rdb.MGet(abs_keys...).Val()
			if err == nil {
				for _, counter := range counters {
					n, err := strconv.ParseInt(counter.(string), 10, 64)
					if err == nil {
						pageviews += n
					}
				}
			}
		}

		var dnt_pageviews int64
		v, err := rdb.Get(fmt.Sprintf("counts:abs:%s:%s:%s", host, host_key, date_key)).Result()
		if err == nil {
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				dnt_pageviews += n
			}
		}

		monthly_hll_keys = append(monthly_hll_keys, hll_keys...)
		monthly_pageviews += pageviews
		monthly_dnt_pageviews += dnt_pageviews
		daily_traffic = append(daily_traffic, Traffic{
			Pageviews: pageviews + dnt_pageviews,
			T: t,
			Visitors:  Estimate_visitors(pageviews, dnt_pageviews, visitors),
		})
	}

	monthly_visitors, _ := rdb.PFCount(monthly_hll_keys...).Result()

	traffic := Traffic{
		Visitors:  Estimate_visitors(monthly_pageviews, monthly_dnt_pageviews, monthly_visitors),
		Pageviews: monthly_pageviews + monthly_dnt_pageviews,
	}
	return traffic, daily_traffic, nil
}

func Init() {
	rdb = redis.NewClient(&redis.Options{})
}
