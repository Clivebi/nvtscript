if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3920.1" );
	script_cve_id( "CVE-2018-13785", "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3214" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:33 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3920-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3920-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183920-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-ibm' package(s) announced via the SUSE-SU-2018:3920-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "java-1_7_0-ibm is updated to Java 7.0 Service Refresh 10 Fix Pack 35
(bsc#1116574):
Class Libraries

 - IJ10934 CVE-2018-13785
 - IJ10935 CVE-2018-3136
 - IJ10895 CVE-2018-3139
 - IJ10932 CVE-2018-3149
 - IJ10894 CVE-2018-3180
 - IJ10933 CVE-2018-3214
 - IJ09315 FLOATING POINT EXCEPTION FROM JAVA.TEXT.DECIMALFORMAT. FORMAT
 - IJ09088 INTRODUCING A NEW PROPERTY FOR TURKEY TIMEZONE FOR PRODUCTS
 NOT IDENTIFYING TRT
 - IJ10800 REMOVE EXPIRING ROOT CERTIFICATES IN IBM JDKAC/AEURA(tm)S CACERTS Java Virtual Machine

 - IJ10931 CVE-2018-3169 JIT Compiler

 - IJ08205 CRASH WHILE COMPILING Security
 - IJ10492 'EC KEYSIZE" );
	script_tag( name: "affected", value: "'java-1_7_0-ibm' package(s) on SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm", rpm: "java-1_7_0-ibm~1.7.0_sr10.35~65.31.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-alsa", rpm: "java-1_7_0-ibm-alsa~1.7.0_sr10.35~65.31.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-devel", rpm: "java-1_7_0-ibm-devel~1.7.0_sr10.35~65.31.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-jdbc", rpm: "java-1_7_0-ibm-jdbc~1.7.0_sr10.35~65.31.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-plugin", rpm: "java-1_7_0-ibm-plugin~1.7.0_sr10.35~65.31.1", rls: "SLES11.0SP3" ) )){
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

