if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1695.1" );
	script_cve_id( "CVE-2019-3681" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:00 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-09 18:06:00 +0000 (Thu, 09 Jul 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1695-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1695-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201695-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'osc' package(s) announced via the SUSE-SU-2020:1695-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for osc to 0.169.1 fixes the following issues:

Security issue fixed:

CVE-2019-3681: Fixed an insufficient validation of network-controlled
 filesystem paths (bsc#1122675).

Non-security issues fixed:

Improved the speed and usability of osc bash completion.

improved some error messages.

osc add: support git@ (private github) or git:// URLs correctly.

Split dependson and whatdependson commands.

Added support for osc build --shell-cmd.

Added pkg-ccache support for osc build.

Added --ccache option to osc getbinaries" );
	script_tag( name: "affected", value: "'osc' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "osc", rpm: "osc~0.169.1~3.20.1", rls: "SLES15.0SP1" ) )){
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

