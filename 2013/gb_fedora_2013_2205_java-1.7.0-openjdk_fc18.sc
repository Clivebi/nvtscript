if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098445.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.865341" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-11 10:14:28 +0530 (Mon, 11 Feb 2013)" );
	script_cve_id( "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0429", "CVE-2013-0432", "CVE-2013-0443", "CVE-2013-0440", "CVE-2013-0442", "CVE-2013-0428", "CVE-2013-0441", "CVE-2013-0435", "CVE-2013-0433", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-0434", "CVE-2013-1478", "CVE-2013-1480" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2013-2205" );
	script_name( "Fedora Update for java-1.7.0-openjdk FEDORA-2013-2205" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.7.0-openjdk'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	script_tag( name: "affected", value: "java-1.7.0-openjdk on Fedora 18" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.9~2.3.5.3.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

