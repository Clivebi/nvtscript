if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2787.1" );
	script_cve_id( "CVE-2021-36221" );
	script_tag( name: "creation_date", value: "2021-08-20 14:52:30 +0000 (Fri, 20 Aug 2021)" );
	script_version( "2021-08-21T02:36:44+0000" );
	script_tag( name: "last_modification", value: "2021-08-21 02:36:44 +0000 (Sat, 21 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-19 15:03:00 +0000 (Thu, 19 Aug 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2787-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2787-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212787-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'go1.15' package(s) announced via the SUSE-SU-2021:2787-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for go1.15 fixes the following issues:

Update to go1.15.15:

go#47473 net/http: panic due to racy read of persistConn after handler
 panic (CVE-2021-36221 bsc#1189162)

go#47347 cmd/go: 'go list -f '{{.Stale}}'' stack overflow with cyclic
 imports

go#47014 cmd/go: go mod vendor: open C:\\Users\\LICENSE: Access is denied.

go#46927 cmd/compile: register conflict between external linker and
 duffzero on arm64

go#46857 runtime: ppc64x binaries randomly segfault on linux 5.13rc6" );
	script_tag( name: "affected", value: "'go1.15' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "go1.15", rpm: "go1.15~1.15.15~1.39.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-doc", rpm: "go1.15-doc~1.15.15~1.39.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-race", rpm: "go1.15-race~1.15.15~1.39.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "go1.15", rpm: "go1.15~1.15.15~1.39.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-doc", rpm: "go1.15-doc~1.15.15~1.39.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-race", rpm: "go1.15-race~1.15.15~1.39.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "go1.15", rpm: "go1.15~1.15.15~1.39.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-doc", rpm: "go1.15-doc~1.15.15~1.39.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-race", rpm: "go1.15-race~1.15.15~1.39.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );
