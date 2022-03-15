if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1490.1" );
	script_cve_id( "CVE-2012-3216", "CVE-2012-5073", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-30 02:29:00 +0000 (Thu, 30 Nov 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1490-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1490-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121490-1/" );
	script_xref( name: "URL", value: "http://www.ibm.com/developerworks/java/jdk/alerts/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'IBM Java 1.4.2' package(s) announced via the SUSE-SU-2012:1490-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBM Java 1.4.2 has been updated to SR13-FP14 which fixes bugs and security issues.

CVEs fixed:
CVE-2012-3216,CVE-2012-5073,CVE-2012-5083,CVE-2012-5083,CVE-
2012-1531,CVE-2012-5081,CVE-2012-5084,CVE-2012-5079" );
	script_tag( name: "affected", value: "'IBM Java 1.4.2' package(s) on SUSE Linux Enterprise Java 10 SP4, SUSE Linux Enterprise Java 11 SP2, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_4_2-ibm", rpm: "java-1_4_2-ibm~1.4.2_sr13.14~0.5.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_4_2-ibm-devel", rpm: "java-1_4_2-ibm-devel~1.4.2_sr13.14~0.5.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_4_2-ibm-jdbc", rpm: "java-1_4_2-ibm-jdbc~1.4.2_sr13.14~0.5.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_4_2-ibm-plugin", rpm: "java-1_4_2-ibm-plugin~1.4.2_sr13.14~0.5.1", rls: "SLES10.0SP4" ) )){
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_4_2-ibm", rpm: "java-1_4_2-ibm~1.4.2_sr13.14~0.2.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_4_2-ibm-jdbc", rpm: "java-1_4_2-ibm-jdbc~1.4.2_sr13.14~0.2.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_4_2-ibm-plugin", rpm: "java-1_4_2-ibm-plugin~1.4.2_sr13.14~0.2.1", rls: "SLES11.0SP2" ) )){
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

