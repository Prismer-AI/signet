import Hero from './components/Hero';
import Demo from './components/Demo';
import Features from './components/Features';
import Footer from './components/Footer';
import { Analytics } from '@vercel/analytics/react';

export default function App() {
  return (
    <>
      <Hero />
      <main>
        <Demo />
        <Features />
      </main>
      <Footer />
      <Analytics />
    </>
  );
}
