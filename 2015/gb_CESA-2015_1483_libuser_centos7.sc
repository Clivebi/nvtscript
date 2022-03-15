if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882230" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-3245", "CVE-2015-3246" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-10 12:58:28 +0530 (Mon, 10 Aug 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libuser CESA-2015:1483 centos7" );
	script_tag( name: "summary", value: "Check the version of libuser" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libuser library implements a standardized interface for manipulating
and administering user and group accounts. Sample applications that are
modeled after applications from the shadow password suite (shadow-utils)
are included in these packages.

Two flaws were found in the way the libuser library handled the /etc/passwd
file. A local attacker could use an application compiled against libuser
(for example, userhelper) to manipulate the /etc/passwd file, which could
result in a denial of service or possibly allow the attacker to escalate
their privileges to root. (CVE-2015-3245, CVE-2015-3246)

Red Hat would like to thank Qualys for reporting these issues.

All libuser users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "libuser on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1483" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-July/021257.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "libuser", rpm: "libuser~0.60~7.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libuser-devel", rpm: "libuser-devel~0.60~7.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libuser-python", rpm: "libuser-python~0.60~7.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

