if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867036" );
	script_version( "2021-07-01T11:00:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-10-29 11:37:01 +0530 (Tue, 29 Oct 2013)" );
	script_cve_id( "CVE-2013-4409", "CVE-2013-4410", "CVE-2013-4411" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-08 21:34:00 +0000 (Fri, 08 Nov 2019)" );
	script_name( "Fedora Update for python-djblets FEDORA-2013-18931" );
	script_tag( name: "affected", value: "python-djblets on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-18931" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-October/119820.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-djblets'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "python-djblets", rpm: "python-djblets~0.7.21~1.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

