if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879353" );
	script_version( "2021-08-24T06:00:58+0000" );
	script_cve_id( "CVE-2021-29424" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 06:00:58 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 13:52:00 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-09 03:04:19 +0000 (Fri, 09 Apr 2021)" );
	script_name( "Fedora: Security Advisory for perl-Net-Netmask (FEDORA-2021-c314017fcc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-c314017fcc" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y7JIPQAY5OZ5D3DA7INQILU7SGHTHMWB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-Net-Netmask'
  package(s) announced via the FEDORA-2021-c314017fcc advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Net::Netmask parses and understands IPv4 and IPv6 CIDR blocks.
  There are also functions to insert a network block into a table and then later look up network
  blocks by an IP address using that table." );
	script_tag( name: "affected", value: "'perl-Net-Netmask' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "perl-Net-Netmask", rpm: "perl-Net-Netmask~2.0001~1.fc32", rls: "FC32" ) )){
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

