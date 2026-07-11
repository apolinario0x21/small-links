// Package geo resolve o país (ISO 3166-1 alpha-2) de um IP usando uma base
// MMDB local (DB-IP Lite). Tudo em processo: o IP nunca sai da aplicação.
package geo

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// Resolver consulta a base MMDB. Nil-safe nas camadas superiores: sem base,
// os chamadores recebem "" e seguem sem geolocalização.
type Resolver struct {
	db *maxminddb.Reader
}

// Open abre a base MMDB no caminho dado. Erro (arquivo ausente/corrompido)
// deve virar warn no chamador — a geolocalização é opcional.
func Open(path string) (*Resolver, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &Resolver{db: db}, nil
}

func (r *Resolver) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// CountryCode devolve o código do país do IP, ou "" para IP inválido,
// privado/loopback ou não encontrado na base.
func (r *Resolver) CountryCode(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return ""
	}
	if r == nil || r.db == nil {
		return ""
	}

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.db.Lookup(ip, &record); err != nil {
		return ""
	}
	return record.Country.ISOCode
}
