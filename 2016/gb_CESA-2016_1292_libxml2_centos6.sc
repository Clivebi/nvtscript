if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882513" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-24 05:26:46 +0200 (Fri, 24 Jun 2016)" );
	script_cve_id( "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libxml2 CESA-2016:1292 centos6" );
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
	script_tag( name: "affected", value: "libxml2 on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1292" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-June/021917.html" );
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
	if(( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.6~21.el6_8.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.7.6~21.el6_8.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.7.6~21.el6_8.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-static", rpm: "libxml2-static~2.7.6~21.el6_8.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

