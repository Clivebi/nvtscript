if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818218" );
	script_version( "2021-09-20T15:26:26+0000" );
	script_cve_id( "CVE-2020-26797" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 15:26:26 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-06 03:15:00 +0000 (Tue, 06 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-06 03:17:21 +0000 (Tue, 06 Apr 2021)" );
	script_name( "Fedora: Security Advisory for mediaconch (FEDORA-2021-3b67623d93)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-3b67623d93" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LRONNLLB5HRSW2DF72XEW3VZTJZLEN4G" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediaconch'
  package(s) announced via the FEDORA-2021-3b67623d93 advisory.

  This VT has been deprecated and is therefore no longer functional." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MediaConch is an implementation checker, policy checker, reporter,
and fixer that targets preservation-level audiovisual files
(specifically Matroska, Linear Pulse Code Modulation (LPCM)
and FF Video Codec 1 (FFV1)).

This project is maintained by MediaArea and funded by PREFORMA.

This package includes the command line interface." );
	script_tag( name: "affected", value: "'mediaconch' package(s) on Fedora 33." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

