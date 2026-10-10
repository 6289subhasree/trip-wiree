import { Background } from "@/components/Background";
import { DemoCard } from "@/components/DemoCard";
import { Header } from "@/components/Header";

export default function Page() {
  return (
    <main className="viewport">
      <section className="screen" id="screen">
        <Background />
        <Header />
        <section className="hero">
          <div className="hero-content">
            <p className="eyebrow">
              <i aria-hidden="true" />
              TripWire · Team HELLCODE · HackInverse 1.0
            </p>
            <h1 className="hero-title">
              <span className="line line-one">
                <span className="line-reveal">Content Is Evidence.</span>
              </span>
              <span className="line line-two">
                <span className="line-reveal">Never Authority.</span>
              </span>
            </h1>
            <p className="hero-copy">
              One hidden sentence in an invoice can make an AI agent export the CRM or redirect a payment. TripWire
              puts one gateway in front of every tool call, so what an agent reads can never decide what it does:{" "}
              <b>ALLOW</b>, <b>BLOCK</b> or <b>REQUIRE_APPROVAL</b>.
            </p>
            <div className="cta-row">
              <a className="primary-cta" href="/demo">
                <span className="label">Run the demo</span>
                <span className="arrow-box" aria-hidden="true">
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                    <path d="M2.5 7h9M7.5 3l4 4-4 4" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </span>
              </a>
              <a className="text-link" href="/arena">
                Attack arena <span aria-hidden="true">↗</span>
              </a>
              <a className="text-link" href="/evidence">
                Evidence <span aria-hidden="true">↗</span>
              </a>
            </div>
          </div>
          <DemoCard />
        </section>
      </section>
    </main>
  );
}
