import { Component,Input, OnInit } from '@angular/core';
import {ActivatedRoute, ParamMap, Router} from '@angular/router';
import { Observable } from 'rxjs/Observable';

import { UserIntentService } from '../user-intent.service';

@Component({
    selector: 'f8-user-intent-view',
    providers: [UserIntentService],
    styleUrls: ['./user-intent-view.component.less'],
    templateUrl: './user-intent-view.component.html'
})

export class UserIntentViewComponent implements OnInit {
    @Input() gatewayConfig;

    public masterTagList: any;
    public modelContent: any = {};
    public addedTags: any;

    constructor(private route: Router, private userIntentService: UserIntentService) {
        window.onhashchange = () => {
            this.onAppLoad();
        };
    }

    onAppLoad(): void {
       this.addedTags = [];
       this.addMasterTagList();
       this.getUnknownComponentEcosystem();
    }

    ngOnInit(): void {
        this.onAppLoad();
    }

    addMasterTagList(): void {
        let masterTagListData: Observable<any> = this.userIntentService
                                                    .getMasterTagList('maven', this.gatewayConfig);

        if (masterTagListData) {
                    masterTagListData.subscribe((data) => {
                        if(data && data.hasOwnProperty("tag_list") && data.tag_list.length){
                            this.masterTagList  = data.tag_list;
                            console.log("successfully fetched master taglist")
                        } else{
                           console.log("master taglist is not proper"); 
                        }
                    },
                    error => {
                        console.log("something unexpected happened while fetching master taglist");
                    });
        }
    }

    getUnknownComponentEcosystem(): void {
        let nextCompToTagData: Observable<any> = this.userIntentService
                                                    .getNextComponent('maven', this.gatewayConfig);

        if (nextCompToTagData) {
                    nextCompToTagData.subscribe((data) => {
                        if(data){
                            let compData = data.split(":");
                            this.modelContent["artifactId"] = compData[0];
                            this.modelContent["groupId"] = compData[1];
                            this.modelContent["name"] = data;
                            console.log("successfully fetched next component")
                        } else{
                           console.log("Next component is not proper"); 
                        }
                    },
                    error => {
                        console.log("something unexpected happened while fetching next component");
                    });
        }
    }

    addTagComponent(): void {
        let userIntentData: any = {
            "ecosystem": "maven",
            "component": "",
            "tags": []
        };
        for(var i =0;i<this.addedTags.length;i++){
           userIntentData.tags.push(this.addedTags[i].value); 
        }
        this.setTagUserIntent(userIntentData);
        //this.moveStackReport();
    }

    setTagUserIntent(userIntentData: any): void {
        let setTagUserIntentData: Observable<any> = this.userIntentService
                                                    .submitUserIntent(userIntentData, this.gatewayConfig);

        if (setTagUserIntentData) {
                    setTagUserIntentData.subscribe((data) => {
                        if(data){
                            console.log("successfully set tags");
                            this.moveStackReport();
                        } else{
                           console.log("Looks like tags are not proper"); 
                        }
                    },
                    error => {
                        console.log("something unexpected happened while setting tags");
                    });
        }
    }

    moveStackReport(ev?:Event): void {
        if(ev){
            ev.preventDefault();
        }
        let api_data: any = {};
        if(this.gatewayConfig){
            api_data["access_token"] = this.gatewayConfig.access_token;
            api_data["route_config"] = this.gatewayConfig.config;
            let api_param = this.gatewayConfig.stack_id +"?"+ JSON.stringify(api_data);
            console.log("move to stack report!!"+ api_param);
            this.route.navigate(['/analyze/' + this.gatewayConfig.stack_id] ,{ queryParams: {api_data: JSON.stringify(api_data) }});
        }
    }

}
