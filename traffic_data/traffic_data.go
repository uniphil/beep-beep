package traffic_data

import (
	"math"
)

type Data []struct {
	X, Y float64
}

func (data Data) Scale(w, h int64, yzero bool) Data {
	PADDING := int64(2)
	xmin := math.Inf(1)
	xmax := math.Inf(-1)
	ymin := math.Inf(1)
	ymax := float64(1)
	for _, d := range data {
		if d.X < xmin {
			xmin = d.X
		}
		if d.X > xmax {
			xmax = d.X
		}
		if d.Y < ymin {
			ymin = d.Y
		}
		if d.Y > ymax {
			ymax = d.Y
		}
	}
	var out Data
	for _, d := range data {
		var y float64
		if yzero {
			y = d.Y * float64(h-PADDING*2) / ymax
		} else {
			y = (d.Y - ymin) * float64(h-PADDING*2) / (ymax - ymin)
		}
		out = append(out, struct{ X, Y float64 }{
			X: (d.X-xmin)*float64(w-PADDING*2)/(xmax-xmin) + float64(PADDING),
			Y: y + float64(PADDING),
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

