import {Component, Input, OnChanges, Output, EventEmitter, ViewEncapsulation} from '@angular/core';

import {UserStackInfoModel, ComponentInformationModel} from '../models/stack-report.model';

@Component({
    selector: 'stack-level-information',
    templateUrl: './stack-level.component.html',
    styleUrls: ['./stack-level.component.scss'],
    encapsulation: ViewEncapsulation.None
})

export class StackLevelComponent {
    @Input() userStack: UserStackInfoModel;
    @Input() outliers: any;

    @Output() changeFilter: EventEmitter<any> = new EventEmitter();

    public securityInfo: any;
    public recommendations: any;
    public stackLevelOutliers: any;
    public licenseAnalysis: any;

    constructor() {}

    ngOnChanges(): void {
        if (this.userStack) {
            this.handleLicenseInformation(this.userStack);
            this.handleSecurityInformation(this.userStack);
        }
        if (this.outliers) {
            this.handleStatistics(this.outliers);
        }
    }

    public handleFilter(filterBy: any): void {
        this.changeFilter.emit(filterBy);
    }

    private handleStatistics(outliers: any): void {
        this.stackLevelOutliers = outliers;
    }

    private sortChartColumnData(array: Array<Array<any>>): Array<Array<any>> {
        return array.sort((a, b) => {
            if (a[1] === b[1]) {
                return 0;
            }
            return a[1] > b[1] ? -1 : 1;
        });
    }

    private handleSecurityInformation(tab: UserStackInfoModel): void {
        let dependencies: Array<ComponentInformationModel> = tab.analyzed_dependencies;
        let security: Array<any> = [];
        let temp: Array<any> = [];
        
        dependencies.forEach((dependency) => {
            security = dependency.security;
            if (security && security.length > 0) {
                let max: any = security.reduce((a, b) => {
                    return parseFloat(a['CVSS']) < parseFloat(b['CVSS']) ? b : a;
                });
                temp.push({
                    name: dependency.name,
                    cve: max
                });
            }
        });
        if (temp.length > 0) {
            let final: any = temp.reduce((a, b) => {
                return parseFloat(a['cve']['CVSS']) < parseFloat(b['cve']['CVSS']) ? b : a;
            });
            let cvssValue: number = final.cve.CVSS;
            let indicator: number;
            let iconClass: string = 'fa fa-shield';
            let displayClass: string = 'progress-bar-warning';

            if (cvssValue < 0) {
                indicator = -1;
            }
            if (cvssValue >= 7.0) {
                indicator = cvssValue;
                iconClass = 'fa fa-shield';
                displayClass = 'progress-bar-danger';
            }
            this.securityInfo = {
                name: final.name,
                cve: final.cve,
                percentage: final.cve.CVSS * 10,
                status: final.cve.CVSS < 7 ? 'moderate' : 'critical',
                iconClass: iconClass,
                displayClass: displayClass
            };
        }
    }

    private handleLicenseInformation(tab: UserStackInfoModel): void {
        this.licenseAnalysis = {
            licenseOutliersCount: 0,
            licenseStackConflictsCount: 0,
            licenseReallyUnknownCount: 0,
            licenseComponentConflictsCount: 0,
            licenseConflictsPartial: [],
            licenseConflictsFull: [],
            stackLicenseText: '',
            status: ''
        };

        if (tab.license_analysis) {
            this.licenseAnalysis.licenseOutliersCount =
                tab.license_analysis.outlier_packages ?
                    tab.license_analysis.outlier_packages.length : 0;
            this.licenseAnalysis.licenseStackConflictsCount =
                tab.license_analysis.conflict_packages ?
                    tab.license_analysis.conflict_packages.length : 0;
            if (tab.license_analysis.unknown_licenses) {
              this.licenseAnalysis.licenseReallyUnknownCount =
                  tab.license_analysis.unknown_licenses.really_unknown ?
                      tab.license_analysis.unknown_licenses.really_unknown.length : 0;
              this.licenseAnalysis.licenseComponentConflictsCount =
                  tab.license_analysis.unknown_licenses.component_conflict ?
                      tab.license_analysis.unknown_licenses.component_conflict.length : 0;
            }
            this.licenseAnalysis.stackLicenseText = tab.license_analysis.f8a_stack_licenses[0];
            if (tab.license_analysis.status.toLowerCase() === 'stackconflict' &&
                tab.license_analysis.conflict_packages &&
                    tab.license_analysis.conflict_packages.length) {
                this.licenseAnalysis.licenseConflictsPartial =
                    tab.license_analysis.conflict_packages.slice(0, 2);
                this.licenseAnalysis.licenseConflictsFull = tab.license_analysis.conflict_packages;
            }
            if (tab.license_analysis.status) {
                this.licenseAnalysis.status = tab.license_analysis.status;
                if (tab.license_analysis.status.toLowerCase() === 'componentconflict') {
                    this.licenseAnalysis.status = 'Unknown';
                }
                if (tab.license_analysis.status.toLowerCase() === 'stackconflict') {
                    this.licenseAnalysis.status = 'Conflict';
                }
            } else {
                this.licenseAnalysis.status = 'failure';
            }
        }
    }
}
