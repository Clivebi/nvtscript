if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123607" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:06:11 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2013-0957" );
	script_tag( name: "insight", value: "ELSA-2013-0957 - java-1.7.0-openjdk security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2013-0957" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2013-0957.html" );
	script_cve_id( "CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Oracle Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.25~2.3.10.3.0.1.el6_4", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-demo", rpm: "java-1.7.0-openjdk-demo~1.7.0.25~2.3.10.3.0.1.el6_4", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.25~2.3.10.3.0.1.el6_4", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-javadoc", rpm: "java-1.7.0-openjdk-javadoc~1.7.0.25~2.3.10.3.0.1.el6_4", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-src", rpm: "java-1.7.0-openjdk-src~1.7.0.25~2.3.10.3.0.1.el6_4", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

