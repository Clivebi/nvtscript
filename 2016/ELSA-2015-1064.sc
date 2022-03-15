if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122870" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-02-05 14:01:39 +0200 (Fri, 05 Feb 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-1064" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-1064" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-1064.html" );
	script_cve_id( "CVE-2013-1753", "CVE-2014-4616", "CVE-2013-1752", "CVE-2014-1912", "CVE-2014-4650", "CVE-2014-7185" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux(7|6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
if(release == "OracleLinux7"){
	if(( res = isrpmvuln( pkg: "python27", rpm: "python27~1.1~20.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python", rpm: "python27-python~2.7.8~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-debug", rpm: "python27-python-debug~2.7.8~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-devel", rpm: "python27-python-devel~2.7.8~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-libs", rpm: "python27-python-libs~2.7.8~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-pip", rpm: "python27-python-pip~1.5.6~5.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-setuptools", rpm: "python27-python-setuptools~0.9.8~5.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-simplejson", rpm: "python27-python-simplejson~3.2.0~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-test", rpm: "python27-python-test~2.7.8~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-tools", rpm: "python27-python-tools~2.7.8~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-wheel", rpm: "python27-python-wheel~0.24.0~2.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-runtime", rpm: "python27-runtime~1.1~20.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-scldevel", rpm: "python27-scldevel~1.1~20.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-tkinter", rpm: "python27-tkinter~2.7.8~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "python27", rpm: "python27~1.1~17.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python", rpm: "python27-python~2.7.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-debug", rpm: "python27-python-debug~2.7.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-devel", rpm: "python27-python-devel~2.7.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-libs", rpm: "python27-python-libs~2.7.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-pip", rpm: "python27-python-pip~1.5.6~5.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-setuptools", rpm: "python27-python-setuptools~0.9.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-simplejson", rpm: "python27-python-simplejson~3.2.0~2.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-test", rpm: "python27-python-test~2.7.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-tools", rpm: "python27-python-tools~2.7.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-python-wheel", rpm: "python27-python-wheel~0.24.0~2.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-runtime", rpm: "python27-runtime~1.1~17.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-scldevel", rpm: "python27-scldevel~1.1~17.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python27-tkinter", rpm: "python27-tkinter~2.7.8~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

