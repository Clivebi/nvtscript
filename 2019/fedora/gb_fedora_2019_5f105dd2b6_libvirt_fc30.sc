if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876422" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2019-10132", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 16:29:00 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-05-26 02:12:27 +0000 (Sun, 26 May 2019)" );
	script_name( "Fedora Update for libvirt FEDORA-2019-5f105dd2b6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-5f105dd2b6" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5RANC4LWZQRVJGJHVWCU6R4CCXQMDD4L" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the FEDORA-2019-5f105dd2b6 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Libvirt is a C toolkit to interact with the virtualization capabilities
of recent versions of Linux (and other OSes). The main package includes
the libvirtd server exporting the virtualization support." );
	script_tag( name: "affected", value: "'libvirt' package(s) on Fedora 30." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~5.1.0~6.fc30", rls: "FC30" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

