package actuary

import (
	"encoding/json"
	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

// 6. Docker Security Operations

func TestCheckImageSprawlSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var imgList imageList
	imgs := imgList.populateImageList(2).images
	container1 := types.Container{ImageID: "1"}
	container2 := types.Container{ImageID: "2"}
	containerLst := []types.Container{container1, container2}

	imagesJSON, err := json.Marshal(imgs)
	containerJSON, err := json.Marshal(containerLst)
	if err != nil {
		t.Errorf("Could not convert process list to json.")
	}
	p1 := callPairing{"/containers/json", containerJSON}
	p2 := callPairing{"/images/json", imagesJSON}
	ts := testTarget.testServer(t, p1, p2)
	res := CheckImageSprawl(*testTarget)
	defer ts.Close()
	assert.Equal(t, "PASS", res.Status, "Correct amount of images, should pass.")
}

func TestCheckImageSprawlFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var imgList imageList
	imgs := imgList.populateImageList(105).images
	container1 := types.Container{ImageID: "1"}
	container2 := types.Container{ImageID: "2"}
	containerLst := []types.Container{container1, container2}

	imagesJSON, err := json.Marshal(imgs)
	containerJSON, err := json.Marshal(containerLst)
	if err != nil {
		t.Errorf("Could not convert process list to json.")
	}
	p1 := callPairing{"/containers/json", containerJSON}
	p2 := callPairing{"/images/json", imagesJSON}
	ts := testTarget.testServer(t, p1, p2)
	res := CheckImageSprawl(*testTarget)
	defer ts.Close()
	assert.Equal(t, "WARN", res.Status, "Over 100 images, should not pass.")
}

func TestCheckContainerSprawlSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var containerList1 typeContainerList
	list1 := containerList1.populateContainerList(10).typeContainers
	containerJSON1, err := json.Marshal(list1)
	if err != nil {
		t.Errorf("Could not convert process list to json.")
	}
	p1 := callPairing{"/containers/json", containerJSON1}
	ts := testTarget.testServer(t, p1)
	res := CheckContainerSprawl(*testTarget)
	defer ts.Close()
	assert.Equal(t, "PASS", res.Status, "Sprawl less than 25, should pass.")
}

func TestCheckContainerSprawlFail(t *testing.T) {
	// PROBLEM: same API call with different parameter passed -- how to mock this?
	// Needs a different response... Can't currently test fail case here
	// var containerList1 typeContainerList
	// var containerList2 typeContainerList
	// list1 := containerList1.populateContainerList(10).typeContainers
	// containerList2 = containerList2.populateContainerList(50)
	// containerJSON1, err := json.Marshal(list1)
	// containerJSON2, err := json.Marshal(containerList2)
	// if err != nil {
	// 	t.Errorf("Could not convert process list to json.")
	// }
	// p1 := callPairing{ "/containers/json", containerJSON1}
	// p2 := callPairing{ "/containers/json?all=true", containerJSON2}
	// ts := testServer(t, p1)
	// res := CheckContainerSprawl(*testTarget)
	// defer ts.Close()
	// if res.Status == "PASS"{
	// 	t.Errorf("More than 25 containers not running, should not pass.")
	// }
}
