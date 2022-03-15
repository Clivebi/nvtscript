if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.4064.1" );
	script_cve_id( "CVE-2018-13785", "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183", "CVE-2018-3214" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:29:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:4064-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:4064-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20184064-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2018:4064-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "java-1_8_0-ibm was updated to Java 8.0 Service Refresh 5 Fix Pack 25
(bsc#1116574)
Class Libraries:

 - IJ10934 CVE-2018-13785
 - IJ10935 CVE-2018-3136
 - IJ10895 CVE-2018-3139
 - IJ10932 CVE-2018-3149
 - IJ10894 CVE-2018-3180
 - IJ10930 CVE-2018-3183
 - IJ10933 CVE-2018-3214
 - IJ09315 FLOATING POINT EXCEPTION FROM JAVA.TEXT.DECIMALFORMAT. FORMAT
 - IJ09088 INTRODUCING A NEW PROPERTY FOR TURKEY TIMEZONE FOR PRODUCTS
 NOT IDENTIFYING TRT
 - IJ10800 REMOVE EXPIRING ROOT CERTIFICATES IN IBM JDKAC/AEURA(tm)S CACERTS.
 - IJ10566 SUPPORT EBCDIC CODE PAGE IBM-274 AC/AEURA' BELGIUM EBCDIC Java Virtual Machine

 - IJ08730 APPLICATION SIGNAL HANDLER NOT INVOKED FOR SIGABRT
 - IJ10453 ASSERTION FAILURE AT CLASSPATHITEM.CPP
 - IJ09574 CLASSLOADER DEFINED THROUGH SYSTEM PROPERTY
 AC/AEURA~JAVA.SYSTEM.CLASS.LOADE RAC/AEURA(tm) IS NOT HONORED.
 - IJ10931 CVE-2018-3169
 - IJ10618 GPU SORT: UNSPECIFIED LAUNCH FAILURE
 - IJ10619 INCORRECT ILLEGALARGUMENTEXCEPTION BECAUSE OBJECT IS NOT AN
 INSTANCE OF DECLARING CLASS ON REFLECTIVE INVOCATION
 - IJ10135 JVM HUNG IN GARBAGECOLLECTORMXBEAN.G ETLASTGCINFO() API
 - IJ10680 RECURRENT ABORTED SCAVENGE ORB

 - IX90187 CLIENTREQUESTIMPL.REINVO KE FAILS WITH
 JAVA.LANG.INDEXOUTOFBOUN DSEXCEPTION Reliability and Serviceability

 - IJ09600 DTFJ AND JDMPVIEW FAIL TO PARSE WIDE REGISTER VALUES Security

 - IJ10492 'EC KEYSIZE
z/OS Extensions

 - PH03889 ADD SUPPORT FOR TRY-WITH-RESOURCES TO COM.IBM.JZOS.ENQUEUE
 - PH03414 ROLLOVER FROM SYE TO SAE FOR ICSF REASON CODE 3059
 - PH04008 ZERTJSSE AC/AEURA' Z SYSTEMS ENCRYPTION READINESS TOOL (ZERT) NEW
 SUPPORT IN THE Z/OS JAVA SDK

This includes the update to Java 8.0 Service Refresh 5 Fix Pack 22:
Java Virtual Machine

 - IJ09139 CUDA4J NOT AVAILABLE ON ALL PLATFORMS JIT Compiler

 - IJ09089 CRASH DURING COMPILATION IN USEREGISTER ON X86-32
 - IJ08655 FLOATING POINT ERROR (SIGFPE) IN ZJ9SYM1 OR ANY VM/JIT MODULE
 ON AN INSTRUCTION FOLLOWING A VECTOR INSTRUCTION
 - IJ08850 CRASH IN ARRAYLIST$ITR.NEXT()
 - IJ09601 JVM CRASHES ON A SIGBUS SIGNAL WHEN ACCESSING A
 DIRECTBYTEBUFFER z/OS Extensions

 - PH02999 JZOS data management classes accept dataset names in code
 pages supported by z/OS system services
 - PH01244 OUTPUT BUFFER TOO SHORT FOR GCM MODE ENCRYPTION USING
 IBMJCEHYBRID

Also the update to Java 8.0 Service Refresh 5 Fix Pack 21 Class Libraries

 - IJ08569 JAVA.IO.IOEXCEPTION OCCURS WHEN A FILECHANNEL IS BIGGER THAN
 2GB ON AIX PLATFORM
 - IJ08570 JAVA.LANG.UNSATISFIEDLIN KERROR WITH JAVA OPTION
 -DSUN.JAVA2D.CMM=SUN.JAV A2D.CMM.KCMS.KCMSSERVICE PROVIDER ON AIX
 PLATFORM Java Virtual Machine

 - IJ08001 30% THROUGHPUT DROP FOR CERTAIN SYNCHRONIZATION WORKLOADS
 - IJ07997 TRACEASSERT IN GARBAGE COLLECTOR(MEMORYSUBSPACE)
JIT Compiler

 - IJ08503 ASSERTION IS HIT DUE TO UNEXPECTED STACK HEIGHT IN DEBUGGING
 MODE
 - IJ08375 CRASH DURING HARDWARE GENERATED GUARDED STORAGE EVENT WITHIN A
 TRANSACTIONAL ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'java-1_8_0-ibm' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE OpenStack Cloud 7." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-alsa", rpm: "java-1_8_0-ibm-alsa~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-devel", rpm: "java-1_8_0-ibm-devel~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-plugin", rpm: "java-1_8_0-ibm-plugin~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-alsa", rpm: "java-1_8_0-ibm-alsa~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-devel", rpm: "java-1_8_0-ibm-devel~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-plugin", rpm: "java-1_8_0-ibm-plugin~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-alsa", rpm: "java-1_8_0-ibm-alsa~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-plugin", rpm: "java-1_8_0-ibm-plugin~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-alsa", rpm: "java-1_8_0-ibm-alsa~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-plugin", rpm: "java-1_8_0-ibm-plugin~1.8.0_sr5.25~30.39.1", rls: "SLES12.0SP4" ) )){
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

