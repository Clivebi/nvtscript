if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0871.1" );
	script_cve_id( "CVE-2013-0401", "CVE-2013-1491", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1563", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2435", "CVE-2013-2440" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-19 01:35:00 +0000 (Tue, 19 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0871-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0871-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130871-1/" );
	script_xref( name: "URL", value: "http://www.ibm.com/developerworks/java/jdk/alerts/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'IBM Java 1.7.0' package(s) announced via the SUSE-SU-2013:0871-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBM Java 1.7.0 has been updated to SR4-FP2 which fixes several bugs and security issues.

[link moved to references]

Security Issue references:

 * CVE-2013-2422
>
 * CVE-2013-1491
>
 * CVE-2013-2435
>
 * CVE-2013-2420
>
 * CVE-2013-2432
>
 * CVE-2013-1569
>
 * CVE-2013-2384
>
 * CVE-2013-2383
>
 * CVE-2013-1557
>
 * CVE-2013-1537
>
 * CVE-2013-2440
>
 * CVE-2013-2429
>
 * CVE-2013-2430
>
 * CVE-2013-1563
>
 * CVE-2013-2394
>
 * CVE-2013-0401
>
 * CVE-2013-2424
>
 * CVE-2013-2419
>
 * CVE-2013-2417
>
 * CVE-2013-2418
>
 * CVE-2013-1540
>
 * CVE-2013-2433
>" );
	script_tag( name: "affected", value: "'IBM Java 1.7.0' package(s) on SUSE Linux Enterprise Java 11 SP2, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm", rpm: "java-1_7_0-ibm~1.7.0_sr4.2~0.6.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-alsa", rpm: "java-1_7_0-ibm-alsa~1.7.0_sr4.2~0.6.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-jdbc", rpm: "java-1_7_0-ibm-jdbc~1.7.0_sr4.2~0.6.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-plugin", rpm: "java-1_7_0-ibm-plugin~1.7.0_sr4.2~0.6.1", rls: "SLES11.0SP2" ) )){
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

