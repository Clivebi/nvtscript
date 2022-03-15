if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0114.1" );
	script_cve_id( "CVE-2016-1000111" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:01 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-13 20:04:00 +0000 (Fri, 13 Mar 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0114-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0114-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170114-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-Twisted' package(s) announced via the SUSE-SU-2017:0114-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-Twisted fixes the following issues:
- CVE-2016-1000111: sets environmental variable HTTP_PROXY based on user
 supplied Proxy request header (bsc#989997)" );
	script_tag( name: "affected", value: "'python-Twisted' package(s) on SUSE Enterprise Storage 3, SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Web Scripting 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "python-Twisted", rpm: "python-Twisted~15.2.1~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-Twisted-debuginfo", rpm: "python-Twisted-debuginfo~15.2.1~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-Twisted-debugsource", rpm: "python-Twisted-debugsource~15.2.1~8.1", rls: "SLES12.0" ) )){
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
