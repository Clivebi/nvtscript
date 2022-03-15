if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868066" );
	script_version( "2020-03-02T07:51:06+0000" );
	script_tag( name: "last_modification", value: "2020-03-02 07:51:06 +0000 (Mon, 02 Mar 2020)" );
	script_tag( name: "creation_date", value: "2014-08-08 05:59:58 +0200 (Fri, 08 Aug 2014)" );
	script_cve_id( "CVE-2014-4966", "CVE-2014-4967", "CVE-2013-4260", "CVE-2013-4259", "CVE-2013-2233" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for ansible FEDORA-2014-8904" );
	script_tag( name: "affected", value: "ansible on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-8904" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-August/136307.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ansible'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC19" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC19"){
	if(( res = isrpmvuln( pkg: "ansible", rpm: "ansible~1.6.10~1.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

