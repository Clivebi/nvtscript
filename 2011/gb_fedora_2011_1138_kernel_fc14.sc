if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-February/053901.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.862842" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2011-1138" );
	script_cve_id( "CVE-2010-4668", "CVE-2010-4073", "CVE-2010-4072", "CVE-2010-3880", "CVE-2010-2962", "CVE-2010-3698", "CVE-2010-2963", "CVE-2010-3904", "CVE-2010-4165", "CVE-2011-0521", "CVE-2010-4346", "CVE-2010-4649", "CVE-2011-0006", "CVE-2010-4648", "CVE-2010-4163" );
	script_name( "Fedora Update for kernel FEDORA-2011-1138" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC14" );
	script_tag( name: "affected", value: "kernel on Fedora 14" );
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
if(release == "FC14"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.35.11~83.fc14", rls: "FC14" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

