if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2590.1" );
	script_cve_id( "CVE-2017-13739", "CVE-2017-13740", "CVE-2017-13741", "CVE-2017-13743" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:52 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-07 01:29:00 +0000 (Thu, 07 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2590-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2590-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172590-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'liblouis' package(s) announced via the SUSE-SU-2017:2590-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for liblouis fixes several issues.
These security issues were fixed:
- CVE-2017-13739: Prevent heap-based buffer overflow in the function
 resolveSubtable() that could have caused DoS or remote code execution
 (bsc#1056101)
- CVE-2017-13740: Prevent stack-based buffer overflow in the function
 parseChars() that could have caused DoS or possibly unspecified other
 impact (bsc#1056097) ()
- CVE-2017-13741: Prevent use-after-free in function
 compileBrailleIndicator() that allowed to cause remote DoS (bsc#1056095)
- CVE_2017-13742: Prevent stack-based buffer overflow in function
 includeFile that allowed to cause remote DoS (bsc#1056093).
- CVE-2017-13743: Prevent buffer overflow triggered in the function
 _lou_showString() that allowed to cause remote DoS (bsc#1056090)" );
	script_tag( name: "affected", value: "'liblouis' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "liblouis", rpm: "liblouis~1.7.0~1.3.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis0", rpm: "liblouis0~1.7.0~1.3.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-louis", rpm: "python-louis~1.7.0~1.3.3.1", rls: "SLES11.0SP4" ) )){
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

