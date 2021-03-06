if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878643" );
	script_version( "2020-11-27T03:36:52+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-27 03:36:52 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-22 04:14:44 +0000 (Sun, 22 Nov 2020)" );
	script_name( "Fedora: Security Advisory for pngcheck (FEDORA-2020-27b168926a)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-27b168926a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GVDOWD23WQTRFRSECHRO5FPDKAKEOORE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pngcheck'
  package(s) announced via the FEDORA-2020-27b168926a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "pngcheck verifies the integrity of PNG, JNG and MNG files (by checking the
internal 32-bit CRCs [checksums] and decompressing the image data), it can
optionally dump almost all of the chunk-level information in the image in
human-readable form. For example, it can be used to print the basic statistics
about an image (dimensions, bit depth, etc.), to list the color and
transparency info in its palette (assuming it has one), or to extract the
embedded text annotations. This is a command-line program with batch
capabilities.

The current release supports all PNG, MNG and JNG chunks, including the newly
approved sTER stereo-layout chunk. It correctly reports errors in all but two
of the images in Chris Nokleberg&#39, s brokensuite-20061204." );
	script_tag( name: "affected", value: "'pngcheck' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "pngcheck", rpm: "pngcheck~2.3.0~4.fc31", rls: "FC31" ) )){
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

