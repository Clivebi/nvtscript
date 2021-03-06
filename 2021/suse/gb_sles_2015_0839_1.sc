if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0839.1" );
	script_cve_id( "CVE-2014-2977", "CVE-2014-2978" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0839-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0839-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150839-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'DirectFB' package(s) announced via the SUSE-SU-2015:0839-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "DirectFB was updated to fix two security issues.
The following vulnerabilities were fixed:
* CVE-2014-2977: Multiple integer signedness errors could allow remote
 attackers to cause a denial of service (crash) and possibly execute
 arbitrary code via the Voodoo interface, which triggers a stack-based
 buffer overflow.
* CVE-2014-2978: Remote attackers could cause a denial of service (crash)
 and possibly execute arbitrary code via the Voodoo interface, which
 triggers an out-of-bounds write." );
	script_tag( name: "affected", value: "'DirectFB' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Workstation Extension 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "DirectFB", rpm: "DirectFB~1.7.1~4.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "DirectFB-debuginfo", rpm: "DirectFB-debuginfo~1.7.1~4.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "DirectFB-debugsource", rpm: "DirectFB-debugsource~1.7.1~4.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib++dfb-1_7-1", rpm: "lib++dfb-1_7-1~1.7.1~4.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib++dfb-1_7-1-debuginfo", rpm: "lib++dfb-1_7-1-debuginfo~1.7.1~4.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1", rpm: "libdirectfb-1_7-1~1.7.1~4.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1-debuginfo", rpm: "libdirectfb-1_7-1-debuginfo~1.7.1~4.1", rls: "SLES12.0" ) )){
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

