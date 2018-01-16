import { Component, OnInit, ViewEncapsulation } from '@angular/core';
import {ActivatedRoute, ParamMap} from '@angular/router';

@Component({
    selector: 'f8-user-intent',
    styleUrls: ['./user-intent.component.less'],
    encapsulation: ViewEncapsulation.None,
    templateUrl: './user-intent.component.html'
})

export class UserIntentComponent implements OnInit {
    public stackUrl: string;
    public apiData: any = {};
    public gateway: any = {};
    public label: string;
    public tokenApi: string;
    public routerLink: string;

    constructor(private route: ActivatedRoute) {
        this.route.paramMap.subscribe((params) => {
            this.label = params.get('id');
        });
        window.onhashchange = () => {
            let url: string = location.hash;
            let id: string = url.replace('#/user-intent/', '');
            let splitParams: Array<string> = id.split('?');
            this.label = splitParams[0];
            this.onAppLoad();
        };
    }

    onAppLoad(): void {
        let url: string = location.hash;
        let id: string = url.replace('#/user-intent/', '');
        let splitParams: Array<string> = id.split('?');
        if (splitParams && splitParams.length > 1) {
            this.apiData = decodeURIComponent(splitParams[1].split('api_data=')[1]);
            try {
                this.apiData = JSON.parse(this.apiData);
            } catch (err) {
                console.log('Error parsing JSON');
            }
            if (this.apiData) {
                this.changeLabel();
            }
        }
    }
    
    changeLabel(): void {
        console.log(this.label);
        if (this.label && this.label.trim() !== '') {
            this.routerLink = '/user-intent/' + this.label;
            // this.gateway['user_key'] = this.apiData['user_key'];
            this.gateway['access_token'] = this.apiData['access_token'];
            this.gateway['config'] = this.apiData['route_config'];
            this.gateway['stack_id'] = this.label
            if(this.apiData['show_modal']){
                this.gateway['modal'] = this.apiData['show_modal'];
            }

            // {
            //     "route_config": {
            //         "api_url": ""
            //     }
            // }

            // In case of 3 scale
            // {
            //     "route_config": {
            //         "api_url": "",
            //         "user_key": ""
            //     }
            // }
            if (this.gateway['config'] && this.gateway['config']['api_url']) {
                let apiHost: string = this.gateway['config']['api_url'];
                if (apiHost.charAt(apiHost.length - 1) !== '/') {
                    apiHost += '/';
                    this.gateway['config']['api_url'] = apiHost;
                }
                this.stackUrl = apiHost + 'api/v1/stack-analyses/' + this.label;
                console.log('=========================');
                console.log(this.gateway);
                console.log(this.stackUrl);
                console.log('=========================');
            }
        }
    }

    ngOnInit(): void {
        this.onAppLoad();
    }


}
