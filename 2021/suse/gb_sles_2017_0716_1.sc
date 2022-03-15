if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0716.1" );
	script_cve_id( "CVE-2016-2183" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 16:11:00 +0000 (Wed, 06 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0716-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0716-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170716-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-ibm' package(s) announced via the SUSE-SU-2017:0716-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_1-ibm fixes the following issues:
Security issue fixed:
- CVE-2016-2183: The DES and Triple DES ciphers, as used in the TLS, SSH,
 and IPSec protocols and
 other protocols and products, have a birthday bound of approximately
 four billion blocks, which makes it easier for remote attackers to
 obtain cleartext data via a birthday attack against a long-duration
 encrypted session, as demonstrated by an HTTPS session using Triple DES
 in CBC mode, aka a 'Sweet32' attack. (bsc#1027038)" );
	script_tag( name: "affected", value: "'java-1_7_0-ibm' package(s) on SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Manager 2.1, SUSE Manager Proxy 2.1, SUSE OpenStack Cloud 5." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm", rpm: "java-1_7_0-ibm~1.7.0_sr10.1~61.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-alsa", rpm: "java-1_7_0-ibm-alsa~1.7.0_sr10.1~61.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-devel", rpm: "java-1_7_0-ibm-devel~1.7.0_sr10.1~61.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-jdbc", rpm: "java-1_7_0-ibm-jdbc~1.7.0_sr10.1~61.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-plugin", rpm: "java-1_7_0-ibm-plugin~1.7.0_sr10.1~61.1", rls: "SLES11.0SP3" ) )){
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

