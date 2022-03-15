if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1305.1" );
	script_cve_id( "CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2437", "CVE-2013-2442", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2459", "CVE-2013-2463", "CVE-2013-2464", "CVE-2013-2465", "CVE-2013-2466", "CVE-2013-2468", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-3009", "CVE-2013-3011", "CVE-2013-3012", "CVE-2013-3743", "CVE-2013-4002" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1305-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1305-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131305-1/" );
	script_xref( name: "URL", value: "http://www.ibm.com/developerworks/java/jdk/alerts/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'IBM Java 1.6.0' package(s) announced via the SUSE-SU-2013:1305-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBM Java 1.6.0 has been updated to SR14 to fix bugs and security issues.

Please see also [link moved to references]

Also the following bugs have been fixed:

 * add Europe/Busingen to tzmappings (bnc#817062)
 * mark files in jre/bin and bin/ as executable
(bnc#823034)
 * check if installed qa_filelist is not empty
(bnc#831936)

Security Issue references:

 * CVE-2013-3009
>
 * CVE-2013-3011
>
 * CVE-2013-3012
>
 * CVE-2013-4002
>
 * CVE-2013-2468
>
 * CVE-2013-2469
>
 * CVE-2013-2465
>
 * CVE-2013-2464
>
 * CVE-2013-2463
>
 * CVE-2013-2473
>
 * CVE-2013-2472
>
 * CVE-2013-2471
>
 * CVE-2013-2470
>
 * CVE-2013-2459
>
 * CVE-2013-2466
>
 * CVE-2013-3743
>
 * CVE-2013-2448
>
 * CVE-2013-2442
>
 * CVE-2013-2407
>
 * CVE-2013-2454
>
 * CVE-2013-2456
>
 * CVE-2013-2453
>
 * CVE-2013-2457
>
 * CVE-2013-2455
>
 * CVE-2013-2412
>
 * CVE-2013-2443
>
 * CVE-2013-2447
>
 * CVE-2013-2437
>
 * CVE-2013-2444
>
 * CVE-2013-2452
>
 * CVE-2013-2446
>
 * CVE-2013-2450
>
 * CVE-2013-1571
>
 * CVE-2013-2451
>
 * CVE-2013-1500
>" );
	script_tag( name: "affected", value: "'IBM Java 1.6.0' package(s) on SUSE Linux Enterprise Server 10 SP3." );
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
if(release == "SLES10.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm", rpm: "java-1_6_0-ibm~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-32bit", rpm: "java-1_6_0-ibm-32bit~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-alsa", rpm: "java-1_6_0-ibm-alsa~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-alsa-32bit", rpm: "java-1_6_0-ibm-alsa-32bit~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-devel", rpm: "java-1_6_0-ibm-devel~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-devel-32bit", rpm: "java-1_6_0-ibm-devel-32bit~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-fonts", rpm: "java-1_6_0-ibm-fonts~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-jdbc", rpm: "java-1_6_0-ibm-jdbc~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-plugin", rpm: "java-1_6_0-ibm-plugin~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-plugin-32bit", rpm: "java-1_6_0-ibm-plugin-32bit~1.6.0_sr14.0~0.6.6.1", rls: "SLES10.0SP3" ) )){
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

