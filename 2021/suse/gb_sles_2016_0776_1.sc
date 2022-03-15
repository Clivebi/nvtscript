if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0776.1" );
	script_cve_id( "CVE-2015-5041", "CVE-2015-7575", "CVE-2015-7981", "CVE-2015-8126", "CVE-2015-8472", "CVE-2015-8540", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-19 16:16:00 +0000 (Wed, 19 Jun 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0776-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0776-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160776-1/" );
	script_xref( name: "URL", value: "http://www.ibm.com/developerworks/java/jdk/alerts/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_6_0-ibm' package(s) announced via the SUSE-SU-2016:0776-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBM Java was updated to version 6.0-16.20, fixing various security issues.
More information can be found on [link moved to references].
Security Issues:
CVE-2015-8540 CVE-2015-7981 CVE-2015-5041 CVE-2016-0494 CVE-2016-0483 CVE-2015-8126 CVE-2015-8472 CVE-2016-0466 CVE-2016-0402 CVE-2015-7575 CVE-2016-0448" );
	script_tag( name: "affected", value: "'java-1_6_0-ibm' package(s) on SUSE Linux Enterprise Server 10 SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm", rpm: "java-1_6_0-ibm~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-32bit", rpm: "java-1_6_0-ibm-32bit~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-alsa", rpm: "java-1_6_0-ibm-alsa~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-alsa-32bit", rpm: "java-1_6_0-ibm-alsa-32bit~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-devel", rpm: "java-1_6_0-ibm-devel~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-devel-32bit", rpm: "java-1_6_0-ibm-devel-32bit~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-fonts", rpm: "java-1_6_0-ibm-fonts~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-jdbc", rpm: "java-1_6_0-ibm-jdbc~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-plugin", rpm: "java-1_6_0-ibm-plugin~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-plugin-32bit", rpm: "java-1_6_0-ibm-plugin-32bit~1.6.0_sr16.20~0.8.1", rls: "SLES10.0SP4" ) )){
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

