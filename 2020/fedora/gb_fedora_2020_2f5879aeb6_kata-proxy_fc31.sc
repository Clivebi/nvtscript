if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878471" );
	script_version( "2021-07-16T11:00:51+0000" );
	script_cve_id( "CVE-2020-2026" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-05 04:15:00 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-18 03:08:54 +0000 (Sun, 18 Oct 2020)" );
	script_name( "Fedora: Security Advisory for kata-proxy (FEDORA-2020-2f5879aeb6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-2f5879aeb6" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6JPBKAQBF3OR72N55GWM2TDYQP2OHK6H" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kata-proxy'
  package(s) announced via the FEDORA-2020-2f5879aeb6 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A proxy for the Kata Containers project

The Kata Containers runtime creates a virtual machine (VM) to isolate
a set of container workloads. The VM requires a guest kernel and a
guest operating system ('guest OS') to boot and create containers
inside the guest environment. This package contains the tools to create
guest OS images.

The kata-proxy is part of the Kata Containers project. For more
information on how the proxy fits into the Kata Containers
architecture, refer to the Kata Containers architecture documentation." );
	script_tag( name: "affected", value: "'kata-proxy' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "kata-proxy", rpm: "kata-proxy~1.11.1~1.fc31.1", rls: "FC31" ) )){
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

