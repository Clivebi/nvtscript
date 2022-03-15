if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.3046.1" );
	script_cve_id( "CVE-2010-2074", "CVE-2016-9422", "CVE-2016-9423", "CVE-2016-9424", "CVE-2016-9425", "CVE-2016-9434", "CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438", "CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442", "CVE-2016-9443", "CVE-2016-9621", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624", "CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628", "CVE-2016-9629", "CVE-2016-9630", "CVE-2016-9631", "CVE-2016-9632", "CVE-2016-9633" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:3046-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:3046-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20163046-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'w3m' package(s) announced via the SUSE-SU-2016:3046-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for w3m fixes the following issues:
- update to debian git version (bsc#1011293) addressed security issues:
 CVE-2016-9621: w3m: global-buffer-overflow write (bsc#1012020)
 CVE-2016-9622: w3m: null deref (bsc#1012021) CVE-2016-9623: w3m: null
 deref (bsc#1012022) CVE-2016-9624: w3m: near-null deref (bsc#1012023)
 CVE-2016-9625: w3m: stack overflow (bsc#1012024) CVE-2016-9626: w3m:
 stack overflow (bsc#1012025) CVE-2016-9627: w3m: heap overflow read +
 deref (bsc#1012026) CVE-2016-9628: w3m: null deref (bsc#1012027)
 CVE-2016-9629: w3m: null deref (bsc#1012028) CVE-2016-9630: w3m:
 global-buffer-overflow read (bsc#1012029) CVE-2016-9631: w3m: null deref
 (bsc#1012030) CVE-2016-9632: w3m: global-buffer-overflow read
 (bsc#1012031) CVE-2016-9633: w3m: OOM (bsc#1012032) CVE-2016-9434: w3m:
 null deref (bsc#1011283) CVE-2016-9435: w3m: use uninit value
 (bsc#1011284) CVE-2016-9436: w3m: use uninit value (bsc#1011285)
 CVE-2016-9437: w3m: write to rodata (bsc#1011286) CVE-2016-9438: w3m:
 null deref (bsc#1011287) CVE-2016-9439: w3m: stack overflow
 (bsc#1011288) CVE-2016-9440: w3m: near-null deref (bsc#1011289)
 CVE-2016-9441: w3m: near-null deref (bsc#1011290) CVE-2016-9442: w3m:
 potential heap buffer corruption (bsc#1011291) CVE-2016-9443: w3m: null
 deref (bsc#1011292)" );
	script_tag( name: "affected", value: "'w3m' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "w3m", rpm: "w3m~0.5.3.git20161120~4.1", rls: "SLES11.0SP4" ) )){
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

