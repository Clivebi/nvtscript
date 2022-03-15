if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.3189.1" );
	script_cve_id( "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7951", "CVE-2016-7952", "CVE-2016-7953" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:3189-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:3189-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20163189-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-libs' package(s) announced via the SUSE-SU-2016:3189-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xorg-x11-libs fixes the following issues:
 - insufficient validation of data from the X server can cause a
 one byte buffer read underrun (bsc#1003023, CVE-2016-7953)
 - insufficient validation of data from the X server can cause out
 of boundary memory access or endless loops (Denial of Service)
 (bsc#1003012, CVE-2016-7951, CVE-2016-7952)
 - insufficient validation of data from the X server can cause out
 of boundary memory writes (bsc#1003000, CVE-2016-7947, CVE-2016-7948)
 - insufficient validation of data from the X server can cause out
 of boundary memory access or endless loops (Denial of Service).
 (bsc#1002998, CVE-2016-7945, CVE-2016-7946)" );
	script_tag( name: "affected", value: "'xorg-x11-libs' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-32bit", rpm: "xorg-x11-libs-32bit~7.4~8.26.49.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs", rpm: "xorg-x11-libs~7.4~8.26.49.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-x86", rpm: "xorg-x11-libs-x86~7.4~8.26.49.1", rls: "SLES11.0SP4" ) )){
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

