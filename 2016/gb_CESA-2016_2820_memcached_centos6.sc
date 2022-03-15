if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882601" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-29 05:39:39 +0100 (Tue, 29 Nov 2016)" );
	script_cve_id( "CVE-2016-8704", "CVE-2016-8705" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for memcached CESA-2016:2820 centos6" );
	script_tag( name: "summary", value: "Check the version of memcached" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "memcached is a high-performance, distributed
memory object caching system, generic in nature, but intended for use in speeding
up dynamic web applications by alleviating database load.

Security Fix(es):

  * Two integer overflow flaws, leading to heap-based buffer overflows, were
found in the memcached binary protocol. An attacker could create a
specially crafted message that would cause the memcached server to crash
or, potentially, execute arbitrary code. (CVE-2016-8704, CVE-2016-8705)" );
	script_tag( name: "affected", value: "memcached on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:2820" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-November/022161.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "memcached", rpm: "memcached~1.4.4~3.el6_8.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "memcached-devel", rpm: "memcached-devel~1.4.4~3.el6_8.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

