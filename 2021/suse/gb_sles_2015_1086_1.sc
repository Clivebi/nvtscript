if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1086.1" );
	script_cve_id( "CVE-2015-0138", "CVE-2015-0192", "CVE-2015-0204", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-1914", "CVE-2015-2808" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1086-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1086-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151086-1/" );
	script_xref( name: "URL", value: "http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_Update_May_2015" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'IBM Java' package(s) announced via the SUSE-SU-2015:1086-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBM Java 1.6.0 was updated to SR16-FP4 fixing security issues and bugs.
Tabulated information can be found on: [link moved to references] CVE-2015-0192 CVE-2015-2808 CVE-2015-1914 CVE-2015-0138 CVE-2015-0491 CVE-2015-0458 CVE-2015-0459 CVE-2015-0469 CVE-2015-0480 CVE-2015-0488 CVE-2015-0478 CVE-2015-0477 CVE-2015-0204" );
	script_tag( name: "affected", value: "'IBM Java' package(s) on SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2, SUSE Manager 1.7." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm", rpm: "java-1_6_0-ibm~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-alsa", rpm: "java-1_6_0-ibm-alsa~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-fonts", rpm: "java-1_6_0-ibm-fonts~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-jdbc", rpm: "java-1_6_0-ibm-jdbc~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-plugin", rpm: "java-1_6_0-ibm-plugin~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm", rpm: "java-1_6_0-ibm~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-alsa", rpm: "java-1_6_0-ibm-alsa~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-devel", rpm: "java-1_6_0-ibm-devel~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-fonts", rpm: "java-1_6_0-ibm-fonts~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-jdbc", rpm: "java-1_6_0-ibm-jdbc~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-plugin", rpm: "java-1_6_0-ibm-plugin~1.6.0_sr16.4~0.3.1", rls: "SLES11.0SP2" ) )){
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
