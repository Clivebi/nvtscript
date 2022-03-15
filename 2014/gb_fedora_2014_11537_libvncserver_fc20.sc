if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868353" );
	script_version( "2020-02-11T08:37:57+0000" );
	script_tag( name: "last_modification", value: "2020-02-11 08:37:57 +0000 (Tue, 11 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-10-01 16:58:32 +0530 (Wed, 01 Oct 2014)" );
	script_cve_id( "CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055", "CVE-2010-5304" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for libvncserver FEDORA-2014-11537" );
	script_tag( name: "affected", value: "libvncserver on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-11537" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-September/139445.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvncserver'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "libvncserver", rpm: "libvncserver~0.9.10~0.6.20140718git9453be42.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

