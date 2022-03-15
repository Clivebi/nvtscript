if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098398.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.865328" );
	script_version( "2020-10-27T07:52:38+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 07:52:38 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-08 10:15:30 +0530 (Fri, 08 Feb 2013)" );
	script_cve_id( "CVE-2013-0170", "CVE-2012-3411", "CVE-2012-4423", "CVE-2012-3445", "CVE-2012-2693" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "FEDORA", value: "2013-1626" );
	script_name( "Fedora Update for libvirt FEDORA-2013-1626" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC17" );
	script_tag( name: "affected", value: "libvirt on Fedora 17" );
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
if(release == "FC17"){
	if(( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~0.9.11.9~1.fc17", rls: "FC17" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

