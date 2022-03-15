if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0645.1" );
	script_cve_id( "CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2657", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:47 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0645-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0645-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180645-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-ibm' package(s) announced via the SUSE-SU-2018:0645-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_0-ibm provides the following fixes:
The version was updated to 7.0.10.20 [bsc#1082810]:
* Following security issues were fixed:
 - CVE-2018-2633 CVE-2018-2637 CVE-2018-2634 CVE-2018-2582 CVE-2018-2641
 CVE-2018-2618 CVE-2018-2657 CVE-2018-2603 CVE-2018-2599 CVE-2018-2602
 CVE-2018-2678 CVE-2018-2677 CVE-2018-2663 CVE-2018-2588 CVE-2018-2579
* Defect fixes:
 - IJ04281 Class Libraries: Startup time increase after applying apar
 IV96905
 - IJ03822 Class Libraries: Update timezone information to tzdata2017c
 - IJ03605 Java Virtual Machine: Legacy security for com.ibm.jvm.dump,
 trace, log was not enabled by default
 - IJ03607 JIT Compiler: Result String contains a redundant dot when
 converted from BigDecimal with 0 on all platforms
 - IX90185 ORB: Upgrade ibmcfw.jar to version O1800.01
 - IJ04282 Security: Change in location and default of jurisdiction
 policy files
 - IJ03853 Security: IBMCAC provider does not support SHA224
 - IJ02679 Security: IBMPKCS11Impl AC/AEURA' Bad sessions are being allocated
 internally
 - IJ02706 Security: IBMPKCS11Impl AC/AEURA' Bad sessions are being allocated
 internally
 - IJ03552 Security: IBMPKCS11Impl - Config file problem with the slot
 specification attribute
 - IJ01901 Security: IBMPKCS11Impl AC/AEURA' SecureRandom.setSeed() exception
 - IJ03801 Security: Issue with same DN certs, iKeyman GUI error with
 stash, JKS Chain issue and JVM argument parse issue with iKeyman
 - IJ02284 JIT Compiler: Division by zero in JIT compiler
 - Make it possible to run Java jnlp files from Firefox. (bsc#1057460)" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm", rpm: "java-1_7_0-ibm~1.7.0_sr10.20~65.13.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-alsa", rpm: "java-1_7_0-ibm-alsa~1.7.0_sr10.20~65.13.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-devel", rpm: "java-1_7_0-ibm-devel~1.7.0_sr10.20~65.13.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-jdbc", rpm: "java-1_7_0-ibm-jdbc~1.7.0_sr10.20~65.13.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-plugin", rpm: "java-1_7_0-ibm-plugin~1.7.0_sr10.20~65.13.1", rls: "SLES11.0SP3" ) )){
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

