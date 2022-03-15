if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879515" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2021-22204" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-16 12:15:00 +0000 (Sun, 16 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-05 03:16:56 +0000 (Wed, 05 May 2021)" );
	script_name( "Fedora: Security Advisory for perl-Image-ExifTool (FEDORA-2021-88d24aa32b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-88d24aa32b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/F6UOBPU3LSHAPRRJNISNVXZ5DSUIALLV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-Image-ExifTool'
  package(s) announced via the FEDORA-2021-88d24aa32b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ExifTool is a Perl module with an included command-line application for
reading and writing meta information in image, audio, and video files.
It reads EXIF, GPS, IPTC, XMP, JFIF, MakerNotes, GeoTIFF, ICC Profile,
Photoshop IRB, FlashPix, AFCP, and ID3 meta information from JPG, JP2,
TIFF, GIF, PNG, MNG, JNG, MIFF, EPS, PS, AI, PDF, PSD, BMP, THM, CRW,
CR2, MRW, NEF, PEF, ORF, DNG, and many other types of images. ExifTool
also extracts information from the maker notes of many digital cameras
by various manufacturers including Canon, Casio, FujiFilm, GE, HP,
JVC/Victor, Kodak, Leaf, Minolta/Konica-Minolta, Nikon, Olympus/Epson,
Panasonic/Leica, Pentax/Asahi, Reconyx, Ricoh, Samsung, Sanyo,
Sigma/Foveon, and Sony." );
	script_tag( name: "affected", value: "'perl-Image-ExifTool' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "perl-Image-ExifTool", rpm: "perl-Image-ExifTool~12.16~3.fc33", rls: "FC33" ) )){
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

