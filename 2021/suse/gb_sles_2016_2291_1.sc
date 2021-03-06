if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2291.1" );
	script_cve_id( "CVE-2015-2059", "CVE-2015-8948", "CVE-2016-6261", "CVE-2016-6262", "CVE-2016-6263" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2291-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2291-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162291-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libidn' package(s) announced via the SUSE-SU-2016:2291-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libidn fixes the following issues:
- CVE-2016-6262 and CVE-2015-8948: Out-of-bounds-read when reading one
 zero byte as input (bsc#990189)
- CVE-2016-6261: Out-of-bounds stack read in idna_to_ascii_4i (bsc#990190)
- CVE-2016-6263: stringprep_utf8_nfkc_normalize reject invalid UTF-8
 (bsc#990191)
- CVE-2015-2059: out-of-bounds read with stringprep on invalid UTF-8
 (bsc#923241)" );
	script_tag( name: "affected", value: "'libidn' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libidn", rpm: "libidn~1.10~6.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libidn-32bit", rpm: "libidn-32bit~1.10~6.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libidn-x86", rpm: "libidn-x86~1.10~6.1", rls: "SLES11.0SP4" ) )){
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

