if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-02/msg00000.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831321" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2011:021" );
	script_cve_id( "CVE-2010-4015" );
	script_name( "Mandriva Update for postgresql MDVSA-2011:021 (postgresql)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1|2010\\.0|2009\\.0)" );
	script_tag( name: "affected", value: "postgresql on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability was discovered and corrected in postgresql:

  Buffer overflow in the gettoken function in
  contrib/intarray/_int_bool.c in the intarray array module in PostgreSQL
  9.0.x before 9.0.3, 8.4.x before 8.4.7, 8.3.x before 8.3.14, and 8.2.x
  before 8.2.20 allows remote authenticated users to cause a denial of
  service (crash) and possibly execute arbitrary code via integers with
  a large number of digits to unspecified functions (CVE-2010-4015).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. This update provides a solution to this vulnerability." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://store.mandriva.com/product_info.php?cPath=149&amp;amp;products_id=490" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_mes5"){
	if(( res = isrpmvuln( pkg: "libecpg8.3_6", rpm: "libecpg8.3_6~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpq8.3_5", rpm: "libpq8.3_5~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3", rpm: "postgresql8.3~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-contrib", rpm: "postgresql8.3-contrib~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-devel", rpm: "postgresql8.3-devel~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-docs", rpm: "postgresql8.3-docs~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-pl", rpm: "postgresql8.3-pl~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-plperl", rpm: "postgresql8.3-plperl~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-plpgsql", rpm: "postgresql8.3-plpgsql~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-plpython", rpm: "postgresql8.3-plpython~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-pltcl", rpm: "postgresql8.3-pltcl~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-server", rpm: "postgresql8.3-server~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64ecpg8.3_6", rpm: "lib64ecpg8.3_6~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pq8.3_5", rpm: "lib64pq8.3_5~8.3.14~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "libecpg8.4_6", rpm: "libecpg8.4_6~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpq8.4_5", rpm: "libpq8.4_5~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4", rpm: "postgresql8.4~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-contrib", rpm: "postgresql8.4-contrib~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-devel", rpm: "postgresql8.4-devel~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-docs", rpm: "postgresql8.4-docs~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-pl", rpm: "postgresql8.4-pl~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-plperl", rpm: "postgresql8.4-plperl~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-plpgsql", rpm: "postgresql8.4-plpgsql~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-plpython", rpm: "postgresql8.4-plpython~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-pltcl", rpm: "postgresql8.4-pltcl~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-server", rpm: "postgresql8.4-server~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64ecpg8.4_6", rpm: "lib64ecpg8.4_6~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pq8.4_5", rpm: "lib64pq8.4_5~8.4.7~0.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.0"){
	if(( res = isrpmvuln( pkg: "libecpg8.4_6", rpm: "libecpg8.4_6~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpq8.4_5", rpm: "libpq8.4_5~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4", rpm: "postgresql8.4~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-contrib", rpm: "postgresql8.4-contrib~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-devel", rpm: "postgresql8.4-devel~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-docs", rpm: "postgresql8.4-docs~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-pl", rpm: "postgresql8.4-pl~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-plperl", rpm: "postgresql8.4-plperl~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-plpgsql", rpm: "postgresql8.4-plpgsql~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-plpython", rpm: "postgresql8.4-plpython~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-pltcl", rpm: "postgresql8.4-pltcl~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.4-server", rpm: "postgresql8.4-server~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64ecpg8.4_6", rpm: "lib64ecpg8.4_6~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pq8.4_5", rpm: "lib64pq8.4_5~8.4.7~0.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2009.0"){
	if(( res = isrpmvuln( pkg: "libecpg8.3_6", rpm: "libecpg8.3_6~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpq8.3_5", rpm: "libpq8.3_5~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3", rpm: "postgresql8.3~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-contrib", rpm: "postgresql8.3-contrib~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-devel", rpm: "postgresql8.3-devel~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-docs", rpm: "postgresql8.3-docs~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-pl", rpm: "postgresql8.3-pl~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-plperl", rpm: "postgresql8.3-plperl~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-plpgsql", rpm: "postgresql8.3-plpgsql~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-plpython", rpm: "postgresql8.3-plpython~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-pltcl", rpm: "postgresql8.3-pltcl~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql8.3-server", rpm: "postgresql8.3-server~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64ecpg8.3_6", rpm: "lib64ecpg8.3_6~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pq8.3_5", rpm: "lib64pq8.3_5~8.3.14~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

