if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131103" );
	script_version( "2020-03-03T07:50:03+0000" );
	script_tag( name: "creation_date", value: "2015-10-26 09:36:02 +0200 (Mon, 26 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-03-03 07:50:03 +0000 (Tue, 03 Mar 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0408" );
	script_tag( name: "insight", value: "When libaudiofile is used to change both the number of channels of an audio file (e.g. from stereo to mono) and the sample format (e.g. from 16-bit samples to 8-bit samples), the output file will contain corrupted data. If the new sample format is smaller than the old one, there is a risk of buffer overflow: e.g. when the input file has 16-bit samples and the output file has 8-bit samples, afReadFrames will treat the buffer to read the samples (argument void *data) as a pointer to int16_t instead of int8_t, therefore it will write past its end (CVE-2015-7747)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0408.html" );
	script_cve_id( "CVE-2015-7747" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0408" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Mageia Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MAGEIA5"){
	if(( res = isrpmvuln( pkg: "audiofile", rpm: "audiofile~0.3.6~4.1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

