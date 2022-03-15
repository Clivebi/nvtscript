if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882602" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-29 05:39:44 +0100 (Tue, 29 Nov 2016)" );
	script_cve_id( "CVE-2016-0718" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-25 15:44:00 +0000 (Mon, 25 Jan 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for expat CESA-2016:2824 centos6" );
	script_tag( name: "summary", value: "Check the version of expat" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Expat is a C library for parsing XML documents.

Security Fix(es):

  * An out-of-bounds read flaw was found in the way Expat processed certain
input. A remote attacker could send specially crafted XML that, when parsed
by an application using the Expat library, would cause that application to
crash or, possibly, execute arbitrary code with the permission of the user
running the application. (CVE-2016-0718)

Red Hat would like to thank Gustavo Grieco for reporting this issue." );
	script_tag( name: "affected", value: "expat on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:2824" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-November/022162.html" );
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
	if(( res = isrpmvuln( pkg: "expat", rpm: "expat~2.0.1~13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "expat-devel", rpm: "expat-devel~2.0.1~13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

