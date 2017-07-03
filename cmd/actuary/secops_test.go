package actuary


import (
	
	"encoding/json"
	"testing"
	"github.com/docker/engine-api/types"
)

//6. Docker Security Operations

func TestCheckImageSprawl(t *testing.T) {
//GET /images/json
//requires mocking server

	var imgList imageList

	imgs := imgList.populateImageList(2).images

	container1 := types.Container{ImageID: "1"}
	container2 := types.Container{ImageID: "2"}

	containerLst := []types.Container{container1, container2}

	for i := 0; i< 2; i++{
		imagesJSON, err := json.Marshal(imgs)
		containerJSON, err := json.Marshal(containerLst)

		if err != nil {
			t.Errorf("Could not convert process list to json.")
		}

		p1 := callPairing{ "/containers/json", containerJSON}
		p2 := callPairing{ "/images/json", imagesJSON}

		ts := testServer(t, p1, p2)
		
		res := CheckImageSprawl(testTarget)

		defer ts.Close()

		if i == 0 && res.Status != "PASS" {
			t.Errorf("Correct amount of images, should pass." )
		}
		if i == 1 && res.Status == "PASS"{
			t.Errorf("Over 100 images, should not pass." )
  		}
		//test fail case
		imgs = imgList.populateImageList(105).images
	
	}	
}

func TestCheckContainerSprawl(t *testing.T) {
//requires mocking server
//PROBLEM: same API call with different parameter passed -- how to mock this? 
	//Needs a different response... Can't currently test fail case here

	var containerList1 typeContainerList
	//var containerList2 typeContainerList

	list1 := containerList1.populateContainerList(10).typeContainers
	//containerList2 = containerList2.populateContainerList(10)	

	for i := 0; i< 2; i++{

		containerJSON1, err := json.Marshal(list1)
		//containerJSON2, err := json.Marshal(containerList2)

		if err != nil {
			t.Errorf("Could not convert process list to json.")
		}

		p1 := callPairing{ "/containers/json", containerJSON1}
		//p2 := callPairing{ "/containers/json?all=true", containerJSON2}

		ts := testServer(t, p1)
		
		res := CheckContainerSprawl(testTarget)

		defer ts.Close()

		if i == 0 && res.Status != "PASS" {
			t.Errorf("Sprawl less than 25, should pass.")
		}
		// if i == 1 && res.Status == "PASS"{
		// 	t.Errorf("More than 25 containers not running, should not pass." )
		// }

		//test fail case
		//containerList2 = containerList2.populateContainerList(50)	
	}
}







