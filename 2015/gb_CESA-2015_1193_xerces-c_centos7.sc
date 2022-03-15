if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882212" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-0252" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-03 11:19:11 +0530 (Fri, 03 Jul 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for xerces-c CESA-2015:1193 centos7" );
	script_tag( name: "summary", value: "Check the version of xerces-c" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Xerces-C is a validating XML parser written
  in a portable subset of C++.

A flaw was found in the way the Xerces-C XML parser processed certain XML
documents. A remote attacker could provide specially crafted XML input
that, when parsed by an application using Xerces-C, would cause that
application to crash. (CVE-2015-0252)

All xerces-c users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue." );
	script_tag( name: "affected", value: "xerces-c on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1193" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-June/021228.html" );
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
	if(( res = isrpmvuln( pkg: "xerces-c", rpm: "xerces-c~3.1.1~7.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-c-devel", rpm: "xerces-c-devel~3.1.1~7.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-c-doc", rpm: "xerces-c-doc~3.1.1~7.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

