if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.14553.1" );
	script_cve_id( "CVE-2020-14360", "CVE-2020-25712" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:48 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-26 18:29:00 +0000 (Tue, 26 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:14553-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:14553-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-202014553-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2020:14553-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xorg-x11-server fixes the following issues:

CVE-2020-25712: Fixed a heap-based buffer overflow which could have led
 to privilege escalation (bsc#1177596).

CVE-2020-14360: Fixed an out of bounds memory accesses on too short
 request which could lead to denial of service (bsc#1174908)." );
	script_tag( name: "affected", value: "'xorg-x11-server' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~7.4~27.122.37.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~7.4~27.122.37.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra", rpm: "xorg-x11-server-extra~7.4~27.122.37.1", rls: "SLES11.0SP4" ) )){
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

