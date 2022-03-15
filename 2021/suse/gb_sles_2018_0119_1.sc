if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0119.1" );
	script_cve_id( "CVE-2016-5823", "CVE-2016-5824", "CVE-2016-5825", "CVE-2016-5826", "CVE-2016-5827", "CVE-2016-9584" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-20 17:26:00 +0000 (Fri, 20 Jan 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0119-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0119-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180119-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libical' package(s) announced via the SUSE-SU-2018:0119-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libical fixes the following issues:
Security issues fixed:
- CVE-2016-5823: The icalproperty_new_clone function in libical 0.47 and
 1.0 allows remote attackers to cause a denial of service
 (use-after-free) via a crafted ics file. (bnc#986632)
- CVE-2016-5824: libical 1.0 allows remote attackers to cause a denial of
 service (use-after-free) via a crafted ics file. (bsc#986639)
- CVE-2016-5825: The icalparser_parse_string function in libical 0.47 and
 1.0 allows remote attackers to cause a denial of service (out-of-bounds
 heap read) via a crafted ics file. (bsc#986642)
- CVE-2016-5826: The parser_get_next_char function in libical 0.47 and 1.0
 allows remote attackers to cause a denial of service (out-of-bounds heap
 read) by crafting a string to the icalparser_parse_string function.
 (bsc#986658)
- CVE-2016-5827: The icaltime_from_string function in libical 0.47 and 1.0
 allows remote attackers to cause a denial of service (out-of-bounds heap
 read) via a crafted string to the icalparser_parse_string function.
 (bsc#986631)
- CVE-2016-9584: libical allows remote attackers to cause a denial of
 service (use-after-free) and possibly read heap memory via a crafted ics
 file. (bnc#1015964)
Bug fixes:
- libical crashes while parsing timezones (bsc#1044995)" );
	script_tag( name: "affected", value: "'libical' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libical0", rpm: "libical0~0.43~1.10.6.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libical0-32bit", rpm: "libical0-32bit~0.43~1.10.6.1", rls: "SLES11.0SP4" ) )){
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

