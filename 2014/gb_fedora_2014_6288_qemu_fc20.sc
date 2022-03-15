if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867794" );
	script_version( "2021-06-11T07:43:31+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 07:43:31 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2014-05-19 11:14:41 +0530 (Mon, 19 May 2014)" );
	script_cve_id( "CVE-2014-0182", "CVE-2014-0142", "CVE-2014-0150", "CVE-2013-4544", "CVE-2014-2894", "CVE-2013-4534", "CVE-2013-4533", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2013-4540", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2013-4531", "CVE-2013-4530", "CVE-2013-4529", "CVE-2013-4527", "CVE-2013-4526", "CVE-2013-4151", "CVE-2013-4150", "CVE-2013-4149", "CVE-2013-4148" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for qemu FEDORA-2014-6288" );
	script_tag( name: "affected", value: "qemu on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-6288" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-May/133345.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
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
	if(( res = isrpmvuln( pkg: "qemu", rpm: "qemu~1.6.2~5.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

