if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882515" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-24 05:27:06 +0200 (Fri, 24 Jun 2016)" );
	script_cve_id( "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libxml2 CESA-2016:1292 centos7" );
	script_tag( name: "summary", value: "Check the version of libxml2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libxml2 library is a development toolbox
providing the implementation of various XML standards.

Security Fix(es):

A heap-based buffer overflow flaw was found in the way libxml2 parsed
certain crafted XML input. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or execute arbitrary code
with the permissions of the user running the application. (CVE-2016-1834,
CVE-2016-1840)

Multiple denial of service flaws were found in libxml2. A remote attacker
could provide a specially crafted XML file that, when processed by an
application using libxml2, could cause that application to crash.
(CVE-2016-1762, CVE-2016-1833, CVE-2016-1835, CVE-2016-1836, CVE-2016-1837,
CVE-2016-1838, CVE-2016-1839, CVE-2016-3627, CVE-2016-3705, CVE-2016-4447,
CVE-2016-4448, CVE-2016-4449)" );
	script_tag( name: "affected", value: "libxml2 on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1292" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-June/021929.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.9.1~6.el7_2.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.9.1~6.el7_2.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.9.1~6.el7_2.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-static", rpm: "libxml2-static~2.9.1~6.el7_2.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

